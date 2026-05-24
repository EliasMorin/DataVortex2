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
})


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

def _search_zip(path: str, targets: list[str]) -> list[dict]:
    results: list[dict] = []
    try:
        with zipfile.ZipFile(path, "r") as zf:
            pw_members = [n for n in zf.namelist() if _is_password_file(n)]
            for member in pw_members:
                try:
                    data    = zf.read(member)
                    text    = data.decode("utf-8", errors="replace")
                    entries = parse_password_file(text)
                    results.extend(_filter_entries(entries, targets, member))
                except Exception:
                    continue
    except Exception:
        pass
    return results


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


def _search_rar(path: str, targets: list[str]) -> list[dict]:
    """
    Extrait et parse les fichiers password depuis un RAR.
    Utilise rarfile.extractall() pour n'extraire que les fichiers cibles
    (efficace même sur des archives de plusieurs Go).
    """
    results: list[dict] = []
    try:
        import rarfile as _rf
    except ImportError:
        return results

    if not _configure_rarfile():
        # Pas d'outil d'extraction disponible → listing seul, pas de lecture
        return results

    tmp_dir = tempfile.mkdtemp(prefix="dv_creds_")
    try:
        with _rf.RarFile(path, "r") as rf:
            pw_members = [n for n in rf.namelist() if _is_password_file(n)]
            if not pw_members:
                return results
            # Extraction ciblée : uniquement les fichiers passwords
            rf.extractall(tmp_dir, members=pw_members)

        # Lecture des fichiers extraits
        for root, _, files in os.walk(tmp_dir):
            for fname in files:
                if not _is_password_file(fname):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                        text = fh.read()
                    rel  = os.path.relpath(fpath, tmp_dir)
                    entries = parse_password_file(text)
                    results.extend(_filter_entries(entries, targets, rel))
                except Exception:
                    continue
    except Exception:
        pass
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return results


# ── Point d'entrée public ─────────────────────────────────────────────────────

def search_credentials(
    path: str, filename: str, targets: list[str]
) -> list[dict]:
    """
    Recherche les credentials correspondant aux domaines `targets` dans une
    archive locale `path`.

    Retourne une liste de dicts :
        { host, login, password, soft, file_path }

    Retourne [] si `targets` est vide, si l'archive ne contient aucun fichier
    password reconnu, ou si aucune entrée ne correspond.
    """
    if not targets:
        return []
    ext = os.path.splitext(filename.lower())[1]
    if ext == ".zip":
        return _search_zip(path, targets)
    if ext == ".rar":
        return _search_rar(path, targets)
    return []
