"""
DataVortex – Intégration Groq AI.

Deux fonctions publiques (async) :
  • ask_groq_structure(sample_paths)  → folder_tree dict ou None
  • ask_groq_password(msg_text)       → mot de passe str ou None

Nécessite GROQ_API_KEY dans l'environnement (ou .env).
Si la clé est absente les fonctions retournent silencieusement None.
"""

import json
import os
from typing import Any

import httpx

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL   = "llama-3.3-70b-versatile"


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {os.environ.get('GROQ_API_KEY', '')}",
        "Content-Type":  "application/json",
    }


def key_available() -> bool:
    """Retourne True si GROQ_API_KEY est défini et non vide."""
    return bool(os.environ.get("GROQ_API_KEY", "").strip())


def _clean_path(path: str) -> str:
    """Garde uniquement les caractères ASCII imprimables et les séparateurs de chemin."""
    return "".join(c for c in path if (c.isascii() and c.isprintable()) or c == "/")


# ── Structure d'archive ───────────────────────────────────────────────────────

async def ask_groq_structure(sample_paths: list[str]) -> dict[str, Any] | None:
    """
    Envoie un échantillon de chemins d'archive à Groq pour identifier les
    codes pays ISO 3166-1 et la structure des dossiers victimes.

    Retourne un folder_tree dict compatible avec parse_country_structure()
    (clés = codes pays + _total_victims + _groq_analyzed + _groq_format +
    _groq_confidence), ou None si Groq ne peut pas aider.
    """
    if not key_available() or not sample_paths:
        return None

    # Nettoie les chemins des caractères non imprimables (garbage RAR) avant envoi
    cleaned   = [_clean_path(p) for p in sample_paths]
    cleaned   = [p for p in cleaned if len(p.strip()) > 2]  # retire les chemins vides / trop courts
    sample    = cleaned[:60] if cleaned else None
    if not sample:
        return None

    paths_text = "\n".join(sample)

    prompt = (
        "Tu analyses une arborescence de stealer logs (données volées).\n"
        "Chaque chemin vient d'une archive ZIP/RAR téléchargée depuis Telegram.\n"
        "Identifie les dossiers qui représentent une victime (un utilisateur infecté) "
        "en cherchant les codes pays ISO 3166-1 alpha-2 (2 lettres, ex: FR, US, AE, BD, GB).\n"
        "Compte le nombre de victimes distinctes par pays (un dossier = une victime).\n\n"
        "Chemins extraits de l'archive :\n"
        f"{paths_text}\n\n"
        "Réponds UNIQUEMENT en JSON valide, sans texte autour :\n"
        '{"countries":[{"code":"FR","count":3},{"code":"AE","count":12}],'
        '"format":"description courte du format de nommage",'
        '"confidence":"high|medium|low"}\n'
        'Si aucun pays détecté : {"countries":[],"format":"inconnu","confidence":"low"}'
    )

    payload: dict[str, Any] = {
        "model":           GROQ_MODEL,
        "messages":        [{"role": "user", "content": prompt}],
        "temperature":     0.1,
        "max_tokens":      512,
        "response_format": {"type": "json_object"},
    }

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(GROQ_API_URL, headers=_headers(), json=payload)
            resp.raise_for_status()
        data = json.loads(resp.json()["choices"][0]["message"]["content"])
    except Exception:
        return None

    countries = data.get("countries") or []
    tree: dict[str, Any] = {}
    total = 0

    for item in countries:
        code  = str(item.get("code", "")).upper().strip()
        count = max(1, int(item.get("count") or 1))
        if len(code) < 2 or len(code) > 4:
            continue
        tree[code] = {"total": count, "with_passwords": 0, "with_cookies": 0, "with_autofill": 0}
        total += count

    if not tree:
        return None

    tree["_total_victims"]    = total
    tree["_groq_analyzed"]    = True
    tree["_groq_format"]      = str(data.get("format", ""))
    tree["_groq_confidence"]  = str(data.get("confidence", "low"))
    return tree


# ── Extraction de mot de passe ────────────────────────────────────────────────

async def ask_groq_password(msg_text: str) -> str | None:
    """
    Tente d'extraire le mot de passe d'une archive depuis un message Telegram.

    Retourne le mot de passe trouvé (str) ou None si rien détecté / clé absente.
    """
    if not key_available() or not msg_text:
        return None

    prompt = (
        "Extrait le mot de passe d'une archive ZIP/RAR depuis ce message Telegram.\n"
        "Le mot de passe peut apparaître après des labels comme : "
        "'pass:', 'password:', 'mdp:', 'pwd:', 'pass =', 'key:', 'clé:', '🔑', "
        "ou simplement seul sur une ligne courte sans autre contexte.\n\n"
        f"Message :\n{msg_text[:600]}\n\n"
        'Réponds UNIQUEMENT en JSON : {"password":"valeur"}\n'
        'Si aucun mot de passe trouvé : {"password":null}'
    )

    payload: dict[str, Any] = {
        "model":           GROQ_MODEL,
        "messages":        [{"role": "user", "content": prompt}],
        "temperature":     0.0,
        "max_tokens":      80,
        "response_format": {"type": "json_object"},
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(GROQ_API_URL, headers=_headers(), json=payload)
            resp.raise_for_status()
        data = json.loads(resp.json()["choices"][0]["message"]["content"])
    except Exception:
        return None

    pwd = data.get("password")
    if not pwd or str(pwd).strip().lower() in ("null", "none", ""):
        return None
    return str(pwd).strip()


# ── Extraction de credentials ciblés (fallback IA) ───────────────────────────

async def ask_groq_credentials(
    file_sample: str, targets: list[str]
) -> list[dict]:
    """
    Fallback IA : quand le parseur standard ne trouve rien, envoie un
    échantillon du fichier à Groq pour extraire les credentials correspondant
    aux domaines cibles, quel que soit le format du fichier.

    Retourne une liste de dicts {host, login, password, soft}.
    """
    if not key_available() or not file_sample.strip() or not targets:
        return []

    targets_str = ", ".join(targets)
    # Limite l'envoi à 3000 chars pour rester dans les tokens
    sample = file_sample[:3000]

    prompt = (
        "Tu analyses un fichier de credentials volés (stealer log).\n"
        f"Extrait UNIQUEMENT les entrées dont l'URL ou le host contient l'un de ces domaines : {targets_str}\n"
        "Le fichier peut avoir n'importe quel format (blocs, CSV, JSON, liste, etc.).\n\n"
        f"Contenu du fichier :\n{sample}\n\n"
        "Réponds UNIQUEMENT en JSON valide :\n"
        '{"credentials":[{"host":"https://...","login":"user@email.com","password":"pass","soft":"Chrome"}]}\n'
        'Si aucune entrée correspondante : {"credentials":[]}'
    )

    payload: dict[str, Any] = {
        "model":           GROQ_MODEL,
        "messages":        [{"role": "user", "content": prompt}],
        "temperature":     0.0,
        "max_tokens":      1024,
        "response_format": {"type": "json_object"},
    }

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(GROQ_API_URL, headers=_headers(), json=payload)
            resp.raise_for_status()
        data = json.loads(resp.json()["choices"][0]["message"]["content"])
    except Exception:
        return []

    results = []
    for entry in data.get("credentials") or []:
        host = str(entry.get("host", "")).strip()
        if not host:
            continue
        results.append({
            "host":     host,
            "login":    str(entry.get("login", "")).strip(),
            "password": str(entry.get("password", "")).strip(),
            "soft":     str(entry.get("soft", "")).strip(),
        })
    return results
