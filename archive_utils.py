"""
DataVortex – Détection des archives ZIP/RAR, chiffrement,
et extraction/découverte dynamique de mots de passe.
"""

import re
import os

# ── Patterns de base (seeds) ──────────────────────────────────────────────────
# Liste de (regex, description). Chargés en DB à la 1ʳᵉ exécution.

SEED_PATTERNS: list[tuple[str, str]] = [
    (
        r"(?:password|pass(?:word)?|pwd|pw|key|mdp|m\.d\.p\.?|mot\s*de\s*passe)\s*[=:\-]\s*(\S+)",
        "Standard keyword=value",
    ),
    (
        r"(?:password|pass(?:word)?|pwd|pw)\s+is\s+[\"']?(\S+?)[\"']?(?:\s|$)",
        "Keyword is value",
    ),
    (
        r"(?:mot\s*de\s*passe|m\.d\.p\.?)\s+est\s+[\"']?(\S+?)[\"']?(?:\s|$)",
        "Français: mdp est value",
    ),
    (
        r"(?:password|pass|pwd|mdp|mot\s*de\s*passe|key)\s*[=:\-]?\s*[\"'`]([^\"'`]+)[\"'`]",
        "Valeur entre guillemets",
    ),
    (
        r"[🔑🗝]\s*[=:\-]?\s*([^\s\n,;]+)",
        "Emoji clé + mot de passe",
    ),
]

# Mots-clés déclencheurs pour la découverte automatique de patterns
_TRIGGER_KEYWORDS = [
    "password", "passwd", "pass",
    "pwd", "pw",
    "mdp", "mot de passe", "m.d.p",
    "key", "passphrase",
]

# ── Détection de type ─────────────────────────────────────────────────────────

ARCHIVE_EXTENSIONS = {".zip", ".rar"}

ARCHIVE_MIMES = {
    "application/zip",
    "application/x-zip-compressed",
    "application/x-zip",
    "application/x-rar-compressed",
    "application/vnd.rar",
    "application/x-rar",
}


def is_archive(filename: str, mime: str) -> bool:
    """Retourne True si le fichier est une archive ZIP ou RAR."""
    ext = os.path.splitext(filename.lower())[1]
    if ext in ARCHIVE_EXTENSIONS:
        return True
    if mime in ARCHIVE_MIMES and ext not in ARCHIVE_EXTENSIONS:
        return True
    return False


# ── Détection du chiffrement ──────────────────────────────────────────────────

def detect_encryption(data: bytes, filename: str) -> bool | None:
    """
    Analyse les premiers octets d'une archive.
    Retourne True (protégée), False (non protégée), None (inconnu).
    """
    if len(data) < 8:
        return None

    # ZIP : parcourt les en-têtes locaux successifs (PK\x03\x04).
    # Bit 0 du champ flags = ZipCrypto. Méthode 99 = AES WinZip.
    # On s'arrête dès qu'un fichier chiffré est trouvé, ou à la fin des données.
    if data[:4] == b"PK\x03\x04":
        pos = 0
        while pos + 30 <= len(data):
            if data[pos : pos + 4] != b"PK\x03\x04":
                break
            flags     = int.from_bytes(data[pos + 6  : pos + 8],  "little")
            method    = int.from_bytes(data[pos + 8  : pos + 10], "little")
            if (flags & 0x01) or method == 99:   # ZipCrypto ou AES WinZip
                return True
            fname_len = int.from_bytes(data[pos + 26 : pos + 28], "little")
            extra_len = int.from_bytes(data[pos + 28 : pos + 30], "little")
            comp_size = int.from_bytes(data[pos + 18 : pos + 22], "little")
            if flags & 0x08:  # data descriptor : comp_size peut être 0 dans l'en-tête
                next_pk = data.find(b"PK\x03\x04", pos + 30 + fname_len + extra_len)
                if next_pk <= pos:
                    break
                pos = next_pk
            else:
                next_pos = pos + 30 + fname_len + extra_len + comp_size
                if next_pos <= pos:
                    break
                pos = next_pos
        return False

    # RAR4 : signature 7 octets
    if data[:7] == b"Rar!\x1a\x07\x00":
        return _rar4_encrypted(data)

    # RAR5 : signature 8 octets
    if data[:8] == b"Rar!\x1a\x07\x01\x00":
        return _rar5_encrypted(data)

    return None


def _rar4_encrypted(data: bytes) -> bool | None:
    pos = 7
    iterations = 0
    while pos + 7 <= len(data) and iterations < 64:
        iterations += 1
        head_type  = data[pos + 2]
        head_flags = int.from_bytes(data[pos + 3 : pos + 5], "little")
        head_size  = int.from_bytes(data[pos + 5 : pos + 7], "little")
        if head_type == 0x73:
            if head_flags & 0x0080:
                return True
        elif head_type == 0x74:
            return bool(head_flags & 0x0004)
        elif head_type == 0x7A:
            break
        if head_size < 7:
            break
        pos += head_size
    return False


def _rar5_encrypted(data: bytes) -> bool | None:
    # RAR5 block types: 1=MAIN, 2=FILE, 3=SERVICE, 4=CRYPT (archive encryption), 5=ENDARC
    # An encrypted archive has a CRYPT block (type 4) right after the signature,
    # BEFORE the main archive header. If we reach a FILE block (type 2) or ENDARC (type 5)
    # without having seen a CRYPT block, the archive is NOT archive-level encrypted.
    pos = 8
    iterations = 0
    while pos + 6 <= len(data) and iterations < 32:
        iterations += 1
        if pos + 4 > len(data):
            break
        pos += 4
        h_size, n = _read_vint(data, pos)
        if n == 0:
            break
        pos += n
        block_end = pos + h_size
        if pos >= len(data):
            break
        h_type, nt = _read_vint(data, pos)
        if nt == 0:
            break
        # Generic header flags are right after h_type; bit 0x0002 = data area present
        h_flags, nf = _read_vint(data, pos + nt) if pos + nt < len(data) else (0, 0)
        if h_type == 4:   # RAWHEAD_CRYPT: archive-level encryption
            return True
        if h_type == 5:   # RAWHEAD_ENDARC: end of archive, no encryption found
            return False
        if h_type == 2:   # RAWHEAD_FILE: file block reached without encryption → not encrypted
            return False
        # Lire add_size depuis l'en-tête (après EXTRA_SIZE optionnel)
        # La DATA_AREA suit directement block_end — pas de vint séparé après
        p = pos + nt + max(nf, 1)
        add_size = 0
        if h_flags & 0x0001:  # EXTRA_DATA : block_extra_size vint
            _, nv = _read_vint(data, p)
            if nv: p += nv
        if h_flags & 0x0002:  # DATA_AREA : add_size vint
            add_size, nv = _read_vint(data, p)
        pos = block_end + add_size
    return False  # parsing exhausted without finding an encryption block


def _read_vint(data: bytes, pos: int) -> tuple[int, int]:
    result, shift = 0, 0
    for i in range(10):
        if pos + i >= len(data):
            return 0, 0
        byte = data[pos + i]
        result |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            return result, i + 1
    return result, 10


# ── Gestion des patterns (dynamique) ─────────────────────────────────────────

# ── Validation du mot de passe extrait ───────────────────────────────────────

def _is_valid_password(value: str) -> bool:
    """
    Retourne False si la valeur extraite est manifestement invalide comme
    mot de passe (trop courte, vide, ou uniquement ponctuation).
    Note : les URLs t.me/ sont acceptées car beaucoup de canaux les utilisent
    littéralement comme mot de passe d'archive.
    """
    if not value or len(value) < 3:
        return False
    # Rejette les valeurs qui ne contiennent que de la ponctuation / espaces
    if all(c in " .,;:!?\"'()[]{}|/-_=+" for c in value):
        return False
    return True


def compile_patterns(pattern_strs: list[str]) -> list[re.Pattern]:
    """Compile une liste de chaînes regex. Ignore les patterns invalides."""
    result = []
    for p in pattern_strs:
        try:
            result.append(re.compile(p, re.IGNORECASE))
        except re.error:
            pass
    return result


def extract_password(
    text: str | None,
    compiled_patterns: list[re.Pattern],
) -> tuple[str | None, str | None]:
    """
    Essaie chaque pattern compilé sur le texte.
    Retourne (mot_de_passe, pattern_str_qui_a_matché) ou (None, None).
    """
    if not text:
        return None, None
    for pat in compiled_patterns:
        m = pat.search(text)
        if m:
            pwd = m.group(1).strip(" .,;:!?\"'()[]{}|")
            if pwd and _is_valid_password(pwd):
                return pwd, pat.pattern
    return None, None


def auto_discover_pattern(
    text: str,
    existing_strs: list[str],
) -> tuple[str, str] | None:
    """
    Tente de découvrir un nouveau pattern depuis un message non matché.

    Cherche la structure :  <mot_clé_connu>  <séparateur>  <valeur>
    Si une combinaison inédite est trouvée et validée, retourne
    (nouveau_pattern_regex, mot_de_passe_extrait).

    Séparateurs reconnus : = : - | / > → ← « » => >> et combinaisons.
    """
    if not text:
        return None

    _SEP = r"([=:\-|>/→←«»]{1,3}|=>|>>|<-)"

    for keyword in sorted(_TRIGGER_KEYWORDS, key=len, reverse=True):
        escaped_kw = re.escape(keyword)
        m = re.search(
            rf"\b{escaped_kw}\b\s*{_SEP}\s*([^\s\n]{{4,60}})",
            text,
            re.IGNORECASE,
        )
        if not m:
            continue

        sep_raw   = m.group(1).strip()
        value_raw = m.group(2).strip(" .,;:!?\"'()[]{}|")

        if len(value_raw) < 4 or not _is_valid_password(value_raw):
            continue

        sep_esc     = re.escape(sep_raw)
        new_pattern = rf"(?:{escaped_kw})\s*{sep_esc}\s*(\S+)"

        if new_pattern in existing_strs:
            continue

        # Valider que le pattern extrait bien la valeur attendue
        try:
            test_compiled = re.compile(new_pattern, re.IGNORECASE)
            test_m = test_compiled.search(text)
            if test_m and test_m.group(1):
                return new_pattern, value_raw
        except re.error:
            continue


# ── Listage du contenu sans extraction ───────────────────────────────────────

def _list_rar4_contents(data: bytes, start_pos: int = 7) -> list[str] | None:
    """
    Extrait les noms de fichiers depuis les premiers octets d'une archive RAR4.
    Les noms se trouvent dans les blocs FILE_HEAD (0x74) avant les données compressées.
    Fonctionne même si les fichiers sont chiffrés individuellement (les noms ne
    sont pas chiffrés). Échoue si l'archive a un chiffrement global (flag 0x0080
    sur le MAIN_HEAD → les en-têtes de fichiers sont eux-mêmes chiffrés).
    `start_pos` permet de démarrer le parsing après les blocs de service
    (quand `data` provient d'un download_exact depuis un offset calculé).
    """
    pos = start_pos  # après signature RAR4 (7 octets) par défaut
    filenames: list[str] = []
    for _ in range(512):
        if pos + 7 > len(data):
            break
        head_type  = data[pos + 2]
        head_flags = int.from_bytes(data[pos + 3 : pos + 5], "little")
        head_size  = int.from_bytes(data[pos + 5 : pos + 7], "little")
        if head_size < 7:
            break

        if head_type == 0x73:  # MAIN_HEAD: chiffrement global → noms illisibles
            if head_flags & 0x0080:
                return None
        elif head_type == 0x74 and pos + 28 <= len(data):  # FILE_HEAD
            name_size   = int.from_bytes(data[pos + 26 : pos + 28], "little")
            # Flag 0x0100 = HIGH_SIZE : 8 octets supplémentaires avant le nom
            name_offset = (pos + 40) if (head_flags & 0x0100) else (pos + 32)
            if 0 < name_size <= 2048 and name_offset + name_size <= len(data):
                raw = data[name_offset : name_offset + name_size]
                fname: str | None = None
                # Essaie d'abord UTF-8 pur
                try:
                    fname = raw.decode("utf-8")
                except UnicodeDecodeError:
                    pass
                # Si le nom contient un octet nul, RAR4 a stocké un nom OEM
                # suivi de la version Unicode compressée (flag 0x0200).
                # Structure : <nom_OEM>\x00<flag_1octet><unicode_compressé…>
                # Pour les noms ASCII, l'unicode compressé est simplement les
                # caractères ASCII un par un → on peut l'extraire directement.
                if fname is None or "\x00" in fname:
                    latin = raw.decode("latin-1")
                    null_idx = latin.find("\x00")
                    if null_idx >= 0 and null_idx + 2 < len(latin):
                        # Saute le nom OEM + le nul + le byte de flag Unicode
                        candidate = latin[null_idx + 2 :]
                        # Garde uniquement les caractères ASCII imprimables
                        clean = "".join(
                            c for c in candidate if 0x20 <= ord(c) <= 0x7E
                        )
                        if len(clean) > 4 and "/" in clean:
                            fname = clean
                if fname is None:
                    for enc in ("cp866", "latin-1"):
                        try:
                            fname = raw.decode(enc)
                            break
                        except (UnicodeDecodeError, ValueError):
                            continue
                if fname:
                    # Supprime les bytes de contrôle résiduels en fin de nom
                    fname = fname.split("\x00")[0]
                    fname = fname.rstrip("\x01\x02\x03\x04\x05\x06\x07\x08"
                                        "\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
                                        "\x11\x12\x13\x14\x15\x16\x17\x18"
                                        "\x19\x1a\x1b\x1c\x1d\x1e\x1f")
                    # Rejette les noms contenant trop de caractères non imprimables
                    # (données compressées interprétées par erreur comme un nom)
                    garbage = sum(1 for c in fname if ord(c) > 127 and not c.isalpha())
                    if garbage <= max(2, len(fname) * 0.25):
                        filenames.append(fname)
        elif head_type == 0x7A:  # ENDARC_HEAD
            break

        # Taille totale du bloc = taille en-tête + données compressées (ADD_SIZE)
        add_size = 0
        if head_flags & 0x8000 and pos + 11 <= len(data):
            add_size = int.from_bytes(data[pos + 7 : pos + 11], "little")
        total = head_size + add_size
        if total <= 0:
            break
        pos += total

    # Return [] (not None) when no encryption detected but no files visible
    # (means file headers are beyond the scanned range, e.g. large service blocks)
    return filenames


def _list_rar5_contents_ex(
    data: bytes, start_pos: int = 8
) -> tuple[list[str] | None, int]:
    """
    Comme _list_rar5_contents mais retourne aussi `next_pos` : l'offset dans
    `data` du premier octet **après** le dernier bloc parsé.  Utilisé par le
    mode séquentiel multi-segment pour enchaîner les téléchargements sans
    brute-force.

    Retourne (None, start_pos) si chiffrement d'archive détecté.
    Retourne ([], start_pos) si aucun bloc visible.
    """
    pos = start_pos
    filenames: list[str] = []
    for _ in range(4096):
        if pos + 6 > len(data):
            break
        pos += 4  # skip CRC32
        h_size, n = _read_vint(data, pos)
        if n == 0:
            break
        pos += n
        block_end = pos + h_size  # fin du header (ADD_SIZE compris)
        if pos >= len(data):
            break
        h_type, nt = _read_vint(data, pos)
        if nt == 0:
            break
        h_flags, nf = _read_vint(data, pos + nt) if pos + nt < len(data) else (0, 0)

        if h_type == 4:   # CRYPT_HEAD: archive chiffré → noms illisibles
            return None, start_pos
        if h_type == 5:   # ENDARC_HEAD
            break

        # Champs optionnels du header commun (après HEAD_TYPE + HEAD_FLAGS)
        p = pos + nt + max(nf, 1)
        add_size = 0
        if h_flags & 0x0001:          # EXTRA_DATA
            _, nv = _read_vint(data, p)
            if nv: p += nv
        if h_flags & 0x0002:          # DATA_AREA
            add_size, nv = _read_vint(data, p)
            if nv: p += nv

        if h_type == 2:   # FILE_HEAD
            ff, nv = _read_vint(data, p)
            if nv > 0:
                p += nv
                _, nv = _read_vint(data, p)      # unpacked_size (toujours présent)
                if nv > 0: p += nv
                _, nv = _read_vint(data, p)      # attributes
                if nv > 0: p += nv
                if ff & 0x0002: p += 4           # mtime
                if ff & 0x0004: p += 4           # CRC32
                _, nv = _read_vint(data, p)      # compression_info
                if nv > 0: p += nv
                _, nv = _read_vint(data, p)      # host_os
                if nv > 0: p += nv
                name_len, nv = _read_vint(data, p)
                if nv > 0 and 0 < name_len <= 2048 and p + nv + name_len <= len(data):
                    p += nv
                    try:
                        decoded = data[p : p + name_len].decode("utf-8", errors="replace")
                        if decoded.count("\ufffd") <= max(2, len(decoded) * 0.15):
                            filenames.append(decoded)
                    except Exception:
                        pass

        # Bloc suivant = fin du header + DATA_AREA
        pos = block_end + add_size

    return filenames, pos


def _list_rar5_contents(data: bytes, start_pos: int = 8) -> list[str] | None:
    """
    Extrait les noms de fichiers depuis les premiers octets d'une archive RAR5.
    Retourne None si le chiffrement d'archive (CRYPT_HEAD type 4) est présent,
    ou [] si aucun fichier visible dans la fenêtre.

    Structure exacte d'un bloc RAR5 (conforme à rarfile/unrar source) :
      [CRC32 : 4 o] [HEAD_SIZE : vint] [HEAD_TYPE : vint] [HEAD_FLAGS : vint]
      [BLOCK_EXTRA_SIZE : vint, si HEAD_FLAGS & 0x0001]  ← taille zone extra
      [ADD_SIZE : vint, si HEAD_FLAGS & 0x0002]          ← taille DATA_AREA
      [...champs spécifiques au type de bloc (inclus dans HEAD_SIZE)...]
      [DATA_AREA : ADD_SIZE octets]  ← données compressées, HORS HEAD_SIZE

    BLOCK_EXTRA_SIZE et ADD_SIZE font partie du header (comptés dans HEAD_SIZE).
    La DATA_AREA suit immédiatement après block_end = pos + HEAD_SIZE.
    => next_block = block_end + ADD_SIZE  (pas de vint séparé après block_end)
    """
    result, _ = _list_rar5_contents_ex(data, start_pos)
    return result


# ── Seek past recovery records ────────────────────────────────────────────────

def _find_rar4_sync(data: bytes, max_scan: int | None = None) -> int:
    """
    Cherche le premier bloc FILE_HEAD (type 0x74) valide dans `data` en scannant
    jusqu'à `max_scan` octets (défaut : totalité de `data`).
    Retourne l'index de début du bloc, ou -1.
    Utilise bytes.find pour parcourir efficacement les grandes zones compressées.
    """
    end = (len(data) - 32) if max_scan is None else min(max_scan, len(data) - 32)
    i = 0
    while i < end:
        # bytes.find est en C : cherche la prochaine occurrence de 0x74 à pos i+2
        pos74 = data.find(b"\x74", i + 2, end + 2)
        if pos74 < 0:
            break
        i = pos74 - 2           # recule de 2 pour pointer sur le début du bloc
        if i < 0:
            i += 1
            continue
        head_flags = int.from_bytes(data[i + 3 : i + 5], "little")
        head_size  = int.from_bytes(data[i + 5 : i + 7], "little")
        if not (32 <= head_size <= 2048):
            i += 1
            continue
        if i + 28 > len(data):
            break
        name_size = int.from_bytes(data[i + 26 : i + 28], "little")
        if not (1 <= name_size <= 512):
            i += 1
            continue
        name_offset = (i + 40) if (head_flags & 0x0100) else (i + 32)
        if name_offset + name_size > len(data):
            i += 1
            continue
        sample = data[name_offset : name_offset + min(name_size, 40)]
        printable = sum(1 for b in sample if 0x20 <= b <= 0x7E)
        if printable >= len(sample) * 0.75:
            return i
        i += 1
    return -1


def _find_rar5_sync(data: bytes, max_scan: int | None = None) -> int:
    """
    Cherche le premier FILE_HEAD RAR5 (type 2) valide en scannant data.
    Validation complète : CRC vint → h_size → h_type=2 → h_flags → champs
    optionnels du bloc commun → file_flags → unpacked_size → attributes →
    mtime/crc32 → compression_info → host_os → name_len → nom UTF-8.
    Retourne l'index du début du bloc, ou -1 si aucun trouvé.

    Une validation aussi profonde est indispensable sur les DATA_AREA chiffrées
    (AES-256) dont les octets semblent aléatoires : sans elle, la plupart des
    positions passent les vérifications superficielles et retournent des noms
    parasites (trop de \ufffd).
    """
    end = (len(data) - 32) if max_scan is None else min(max_scan, len(data) - 32)
    for i in range(end):
        pos = i + 4                   # saute le CRC32
        h_size, n = _read_vint(data, pos)
        if n == 0 or not (4 <= h_size <= 4096):
            continue
        pos += n
        block_end = pos + h_size
        if block_end > len(data):
            continue
        h_type, nt = _read_vint(data, pos)
        if nt == 0 or h_type != 2:    # 2 = FILE_HEAD
            continue
        h_flags, nf = _read_vint(data, pos + nt) if pos + nt < len(data) else (0, 0)
        if nf == 0:
            continue

        # Champs optionnels du bloc commun
        p = pos + nt + nf
        add_size = 0
        ok = True
        if h_flags & 0x0001:
            _, nv = _read_vint(data, p)
            if nv == 0: ok = False
            else: p += nv
        if ok and (h_flags & 0x0002):
            add_size, nv = _read_vint(data, p)
            if nv == 0: ok = False
            else: p += nv
        if not ok:
            continue

        # Champs spécifiques FILE_HEAD
        ff, nv = _read_vint(data, p)
        if nv == 0: continue
        p += nv
        _, nv = _read_vint(data, p)      # unpacked_size (toujours présent)
        if nv == 0: continue
        p += nv
        _, nv = _read_vint(data, p)      # attributes
        if nv == 0: continue
        p += nv
        if ff & 0x0002: p += 4           # mtime
        if ff & 0x0004: p += 4           # CRC32
        _, nv = _read_vint(data, p)      # compression_info
        if nv == 0: continue
        p += nv
        _, nv = _read_vint(data, p)      # host_os
        if nv == 0: continue
        p += nv
        name_len, nv = _read_vint(data, p)  # name_len
        if nv == 0 or not (1 <= name_len <= 1024): continue
        if p + nv + name_len > len(data): continue
        p += nv
        # Le nom doit être un chemin UTF-8 lisible
        raw_name = data[p : p + name_len]
        decoded = raw_name.decode("utf-8", errors="replace")
        if decoded.count("\ufffd") > max(1, len(decoded) * 0.05):
            continue
        if "/" not in decoded and "\\" not in decoded and "." not in decoded:
            continue
        return i
    return -1


def list_rar_segment(data: bytes, is_rar5: bool = False) -> list[str]:
    """
    Extrait les noms de fichiers depuis un segment RAR **arbitraire**.

    RAR4 : scan brute-force indépendant — chaque position dont le 3e octet
    vaut 0x74 est évaluée séparément.  ADD_SIZE n'est jamais utilisé pour
    avancer le pointeur, donc un recovery record ou un gros fichier ne peut
    pas dérailler le scan.

    RAR5 : synchronisation heuristique classique (moins de faux positifs car
    la structure vint est plus contraignante).

    Retourne la liste triée des noms trouvés, ou [] si aucun fichier détecté.
    """
    if is_rar5:
        sync = _find_rar5_sync(data)
        if sync < 0:
            return []
        result = _list_rar5_contents(data, start_pos=sync)
        return sorted(result) if result else []

    # ── RAR4 brute-force scan ─────────────────────────────────────────────
    seen:  set[str]  = set()
    fnames: list[str] = []
    end = len(data) - 32
    i   = 0
    while i < end:
        # bytes.find est en C : cherche 0x74 à position i+2 (= HEAD_TYPE)
        pos74 = data.find(b"\x74", i + 2, end + 2)
        if pos74 < 0:
            break
        i = pos74 - 2
        if i < 0:
            i += 1
            continue
        if i + 28 > len(data):
            break
        head_flags = int.from_bytes(data[i + 3 : i + 5], "little")
        head_size  = int.from_bytes(data[i + 5 : i + 7], "little")
        if not (32 <= head_size <= 2048):
            i += 1
            continue
        name_size = int.from_bytes(data[i + 26 : i + 28], "little")
        if not (1 <= name_size <= 512):
            i += 1
            continue
        name_offset = (i + 40) if (head_flags & 0x0100) else (i + 32)
        if name_offset + name_size > len(data):
            i += 1
            continue
        sample = data[name_offset : name_offset + min(name_size, 40)]
        printable = sum(1 for b in sample if 0x20 <= b <= 0x7E)
        if printable < len(sample) * 0.75:
            i += 1
            continue
        name_bytes = data[name_offset : name_offset + name_size]
        fname  = name_bytes.decode("utf-8", errors="replace")
        garbage = sum(1 for c in fname if ord(c) > 127 and not c.isalpha())
        if garbage <= max(2, len(fname) * 0.25) and fname not in seen:
            seen.add(fname)
            fnames.append(fname)
        i += 1
    return sorted(fnames)


def find_rar4_far_block_end(data: bytes) -> int | None:
    """
    Parcourt les blocs RAR4 (y compris les FILE_HEADs — ne s'arrête PAS à eux)
    et retourne l'offset absolu de fin du premier bloc dont ADD_SIZE dépasse
    le buffer `data`.

    Cas typique : un recovery record suit quelques FILE_HEADs et repousse les
    victimes restantes bien au-delà des 2 Mo initiaux.  Cette fonction retourne
    l'offset où commencent les prochains blocs APRÈS ce gros bloc, afin que le
    multi-segment puisse y placer ses sondes.

    Retourne None si aucun tel bloc n'existe (tout tient dans `data`).
    """
    if len(data) < 7 or data[:7] != b"Rar!\x1a\x07\x00":
        return None
    pos = 7
    for _ in range(256):
        if pos + 7 > len(data):
            return None  # le parser manque d'octets sans avoir rencontré de grand bloc
        head_flags = int.from_bytes(data[pos + 3 : pos + 5], "little")
        head_size  = int.from_bytes(data[pos + 5 : pos + 7], "little")
        if head_size < 7:
            return None
        add_size = 0
        if head_flags & 0x8000 and pos + 11 <= len(data):
            add_size = int.from_bytes(data[pos + 7 : pos + 11], "little")
        total = head_size + add_size
        if total <= 0:
            return None
        next_pos = pos + total
        if next_pos > len(data):
            return next_pos  # offset absolu de fin de ce bloc
        head_type = data[pos + 2]
        if head_type == 0x7A:      # ENDARC
            return None
        pos = next_pos
    return None


def find_rar5_far_block_end(data: bytes) -> int | None:
    """
    Même sémantique que find_rar4_far_block_end pour les archives RAR5.
    """
    if len(data) < 8 or data[:8] != b"Rar!\x1a\x07\x01\x00":
        return None
    pos = 8
    for _ in range(256):
        if pos + 6 > len(data):
            return None
        crc_pos = pos
        pos += 4
        h_size, n = _read_vint(data, pos)
        if n == 0 or h_size < 4:
            return None
        pos += n
        block_end = pos + h_size
        if pos >= len(data):
            return crc_pos
        h_type, nt = _read_vint(data, pos)
        if nt == 0:
            return None
        h_flags, nf = _read_vint(data, pos + nt) if pos + nt < len(data) else (0, 0)
        # Lire add_size depuis l'en-tête (conforme à la spec RAR5)
        p2 = pos + nt + max(nf, 1)
        add_size = 0
        if h_flags & 0x0001:
            _, nv = _read_vint(data, p2)
            if nv: p2 += nv
        if h_flags & 0x0002:
            add_size, _ = _read_vint(data, p2)
        next_pos = block_end + add_size
        if next_pos > len(data):
            return next_pos        # offset absolu de fin de ce bloc
        if h_type == 5:            # ENDARC
            return None
        pos = next_pos
    return None


def find_rar4_resume_offset(data: bytes) -> int | None:
    """
    Parcourt les blocs d'en-tête RAR4 et retourne l'offset absolu (dans le
    fichier original) du premier FILE_HEAD, en sautant les blocs de service /
    récupération dont ADD_SIZE peut valoir des centaines de Mo.

    Retourne None si :
    - ce n'est pas un RAR4 valide
    - des FILE_HEADs sont déjà visibles dans `data` (pas besoin de sauter)
    - l'archive est globalement chiffrée

    Utilisation :
        offset = find_rar4_resume_offset(first_2mb)
        if offset:
            resumed = await download_exact(client, media, offset, RAR_LISTING_BYTES)
            file_list = list_rar_contents_at(resumed, is_rar5=False)
    """
    if len(data) < 7 or data[:7] != b"Rar!\x1a\x07\x00":
        return None
    pos = 7
    for _ in range(64):
        if pos + 7 > len(data):
            # pos est maintenant au-delà de notre fenêtre de 2 Mo mais reste
            # un offset absolu valide dans le fichier source.
            return pos
        head_type  = data[pos + 2]
        head_flags = int.from_bytes(data[pos + 3 : pos + 5], "little")
        head_size  = int.from_bytes(data[pos + 5 : pos + 7], "little")
        if head_size < 7:
            return None

        add_size = 0
        if head_flags & 0x8000 and pos + 11 <= len(data):
            add_size = int.from_bytes(data[pos + 7 : pos + 11], "little")

        if head_type == 0x74:          # FILE_HEAD déjà visible → pas besoin de sauter
            return None
        if head_type == 0x7A:          # ENDARC
            return None
        if head_type == 0x73 and (head_flags & 0x0080):  # MAIN_HEAD chiffrement global
            return None

        total = head_size + add_size
        if total <= 0:
            return None
        pos += total  # peut dépasser len(data) — c'est voulu (offset absolu)
    return None


def find_rar5_resume_offset(data: bytes) -> int | None:
    """
    Parcourt les blocs d'en-tête RAR5 et retourne l'offset absolu du premier
    FILE_HEAD (type 2), en sautant les blocs de service volumineux.
    Même sémantique que find_rar4_resume_offset.
    """
    if len(data) < 8 or data[:8] != b"Rar!\x1a\x07\x01\x00":
        return None
    pos = 8
    for _ in range(64):
        if pos + 6 > len(data):
            return pos  # offset absolu valide
        pos += 4  # skip CRC32
        h_size, n = _read_vint(data, pos)
        if n == 0:
            return None
        pos += n
        block_end = pos + h_size
        if pos >= len(data):
            return pos
        h_type, nt = _read_vint(data, pos)
        if nt == 0:
            return None
        h_flags, nf = _read_vint(data, pos + nt) if pos + nt < len(data) else (0, 0)

        if h_type == 4:   # CRYPT_HEAD — chiffrement global
            return None
        if h_type == 5:   # ENDARC
            return None
        if h_type == 2:   # FILE_HEAD — déjà visible
            return None

        # Lire add_size depuis l'en-tête (conforme à la spec RAR5)
        p3 = pos + nt + max(nf, 1)
        add_size = 0
        if h_flags & 0x0001:
            _, nv = _read_vint(data, p3)
            if nv: p3 += nv
        if h_flags & 0x0002:
            add_size, _ = _read_vint(data, p3)
        pos = block_end + add_size
    return None


def list_rar_contents_at(data: bytes, is_rar5: bool = False) -> list[str]:
    """
    Parse les blocs RAR depuis `data` qui commence directement à un bloc
    (sans signature en début — utilisé après un download_exact à un offset calculé).
    Retourne la liste triée des noms de fichiers, ou [] si rien de visible.
    """
    result = _list_rar5_contents(data, start_pos=0) if is_rar5 \
             else _list_rar4_contents(data, start_pos=0)
    return sorted(result) if result else []


def parse_zip_eocd(data: bytes, data_offset: int) -> tuple[int, int] | None:
    """
    Recherche l'EOCD (PK\\x05\\x06) dans data et retourne
    (cd_offset_absolu, cd_size). Gère ZIP standard et ZIP64.
    Retourne None si l'EOCD n'est pas trouvé.
    """
    eocd = data.rfind(b"PK\x05\x06")
    if eocd == -1 or eocd + 22 > len(data):
        return None

    cd_size   = int.from_bytes(data[eocd + 12 : eocd + 16], "little")
    cd_offset = int.from_bytes(data[eocd + 16 : eocd + 20], "little")

    # ZIP64 : cd_offset == 0xFFFFFFFF
    if cd_offset == 0xFFFF_FFFF:
        loc64 = data.rfind(b"PK\x06\x07", 0, eocd)
        if loc64 == -1 or loc64 + 20 > len(data):
            return None
        eocd64_abs = int.from_bytes(data[loc64 + 8 : loc64 + 16], "little")
        eocd64_idx = eocd64_abs - data_offset
        if not (0 <= eocd64_idx <= len(data) - 56):
            return None
        cd_offset = int.from_bytes(data[eocd64_idx + 48 : eocd64_idx + 56], "little")
        cd_size   = int.from_bytes(data[eocd64_idx + 40 : eocd64_idx + 48], "little")

    return cd_offset, cd_size


def _parse_raw_central_directory(cd_bytes: bytes) -> list[str] | None:
    """
    Parse les entrées PK\\x01\\x02 depuis un bloc brut du répertoire central ZIP.
    Ne nécessite pas l'EOCD dans le buffer : fonctionne aussi sur des données
    partielles (CD tronqué). Retourne None si aucune entrée trouvée.
    """
    # Cherche le premier PK\x01\x02 (tolérance si quelques octets parasites)
    start = cd_bytes.find(b"PK\x01\x02")
    if start == -1:
        return None

    filenames: list[str] = []
    pos = start
    while pos + 46 <= len(cd_bytes):
        if cd_bytes[pos : pos + 4] != b"PK\x01\x02":
            break
        flags       = int.from_bytes(cd_bytes[pos + 8  : pos + 10], "little")
        fname_len   = int.from_bytes(cd_bytes[pos + 28 : pos + 30], "little")
        extra_len   = int.from_bytes(cd_bytes[pos + 30 : pos + 32], "little")
        comment_len = int.from_bytes(cd_bytes[pos + 32 : pos + 34], "little")
        if pos + 46 + fname_len > len(cd_bytes):
            break
        raw      = cd_bytes[pos + 46 : pos + 46 + fname_len]
        encoding = "utf-8" if (flags & 0x0800) else "cp437"
        try:
            filenames.append(raw.decode(encoding, errors="replace"))
        except Exception:
            filenames.append(raw.decode("latin-1", errors="replace"))
        pos += 46 + fname_len + extra_len + comment_len

    return filenames if filenames else None


def _list_zip_from_end(data_end: bytes, tail_offset: int) -> list[str] | None:
    """
    Parse le répertoire central ZIP (Central Directory) depuis les derniers
    octets du fichier. Supporte ZIP standard et ZIP64.

    data_end    : octets téléchargés depuis tail_offset
    tail_offset : position dans le fichier où data_end commence
    """
    eocd_info = parse_zip_eocd(data_end, tail_offset)
    if eocd_info is None:
        return None
    cd_offset, cd_size = eocd_info

    # Le répertoire central doit être dans data_end
    cd_start = cd_offset - tail_offset
    cd_end   = cd_start + cd_size
    if cd_start < 0 or cd_end > len(data_end):
        return None

    return _parse_raw_central_directory(data_end[cd_start:cd_end])


def _list_zip_from_start(data_start: bytes) -> list[str] | None:
    """
    Fallback ZIP : parcourt les en-têtes locaux (Local File Headers) depuis le
    début du fichier. Moins complet que le répertoire central (ne voit que les
    premiers fichiers dans les 4 Ko téléchargés) mais ne nécessite pas de tail.
    """
    pos       = 0
    filenames: list[str] = []
    while pos + 30 <= len(data_start):
        if data_start[pos : pos + 4] != b"PK\x03\x04":
            break
        flags     = int.from_bytes(data_start[pos + 6  : pos + 8],  "little")
        comp_size = int.from_bytes(data_start[pos + 18 : pos + 22], "little")
        fname_len = int.from_bytes(data_start[pos + 26 : pos + 28], "little")
        extra_len = int.from_bytes(data_start[pos + 28 : pos + 30], "little")
        if pos + 30 + fname_len > len(data_start):
            break
        raw      = data_start[pos + 30 : pos + 30 + fname_len]
        encoding = "utf-8" if (flags & 0x0800) else "cp437"
        try:
            fname = raw.decode(encoding, errors="replace")
        except Exception:
            fname = raw.decode("latin-1", errors="replace")
        if not fname.endswith("/"):  # ignorer les entrées de dossier
            filenames.append(fname)
        if flags & 0x08:  # data descriptor : comp_size inconnu → impossible de naviguer
            break
        next_pos = pos + 30 + fname_len + extra_len + comp_size
        if next_pos <= pos:
            break
        pos = next_pos

    return filenames if filenames else None


def list_archive_contents(
    data_start: bytes,
    filename: str,
    data_end: bytes = b"",
    tail_offset: int = 0,
    cd_raw: bytes = b"",
) -> list[str] | None:
    """
    Tente de lister les fichiers d'une archive sans l'extraire.
    - ZIP  : utilise cd_raw (répertoire central brut) en priorité, sinon
             le répertoire central via tail, sinon les en-têtes locaux.
    - RAR4 : parcourt les FILE_HEAD depuis le début.
    - RAR5 : parcourt les blocs FILE depuis le début.
    Retourne la liste triée des noms, ou None si le listage est impossible.
    """
    if data_start[:4] == b"PK\x03\x04":
        if cd_raw:
            result = _parse_raw_central_directory(cd_raw)
            if result is not None:
                return sorted(result)
        if data_end:
            result = _list_zip_from_end(data_end, tail_offset)
            if result is not None:
                return sorted(result)
        result = _list_zip_from_start(data_start)
        return sorted(result) if result else None

    if data_start[:7] == b"Rar!\x1a\x07\x00":
        result = _list_rar4_contents(data_start)
        if result is None:
            return None  # Chiffrement global, en-têtes illisibles
        return sorted(result)  # [] = aucun fichier visible dans la plage scannée

    if data_start[:8] == b"Rar!\x1a\x07\x01\x00":
        result = _list_rar5_contents(data_start)
        if result is None:
            return None  # Chiffrement global, en-têtes illisibles
        return sorted(result)  # [] = aucun fichier visible dans la plage scannée

    return None


def list_local_archive(path: str, filename: str) -> list[str] | None:
    """
    Liste le contenu d'une archive **téléchargée localement**.
    - ZIP  : utilise le module stdlib `zipfile` (Central Directory).
    - RAR4/5 : utilise `rarfile` si disponible, sinon notre parser maison.
    Retourne la liste triée des fichiers (sans les entrées de dossiers),
    ou None si le listage est impossible (archive chiffrée ou corrompue).
    """
    import zipfile as _zipfile
    ext = os.path.splitext(filename.lower())[1]
    try:
        if ext == ".zip":
            with _zipfile.ZipFile(path, "r") as zf:
                return sorted(
                    info.filename
                    for info in zf.infolist()
                    if not info.filename.endswith("/")
                )

        if ext == ".rar":
            # Essai avec rarfile (lecture pure Python des en-têtes, sans unrar)
            try:
                import rarfile as _rarfile
                _rarfile.UNRAR_TOOL = None   # désactive unrar pour le listing seul
                with _rarfile.RarFile(path, "r") as rf:
                    return sorted(f for f in rf.namelist() if not f.endswith("/"))
            except ImportError:
                pass                          # rarfile non installé → fallback
            except Exception:
                return None                   # chiffré, corrompu, split, etc.

            # Fallback : lecture entière + parseur maison (RAM-intensif)
            with open(path, "rb") as fh:
                data = fh.read()
            if data[6:7] == b"\x01":   # RAR5
                result = _list_rar5_contents(data, 8)
            else:                       # RAR4
                result = _list_rar4_contents(data, 7)
            return sorted(result) if result is not None else None

    except Exception:
        return None
    return None


# ── Structure par pays ────────────────────────────────────────────────────────

# ── Formats de dossiers victimes connus ──────────────────────────────────────
#
# Format 1 – BRZCLOUD/Trident : CC_IP_DD.MM.YYYY ou CC_nom_DD.MM.YYYY
#   Ex : AE_5.193.130.89_20.05.2026_01-59-10  /  EG_sVaoi_19.05.2026
_RE_F1 = re.compile(
    r'^([A-Z]{2,4})_[\w.\-]+_\d{1,2}[.\-]\d{1,2}[.\-]\d{2,4}',
    re.IGNORECASE,
)
# Format 2 – POWERCLOUD : CC_IPv4 (sans date)
#   Ex : AE_109.177.19.81
_RE_F2 = re.compile(
    r'^([A-Z]{2,4})_(?:\d{1,3}\.){3}\d{1,3}(?:$|[/_ ])',
    re.IGNORECASE,
)
# Format 3 – HARMONYLOGS/priv : CCGUID_YYYY_MM_DD (GUID tout-caps contient au
#   moins un chiffre)
#   Ex : AE0W8KTBXMK7EFA9YELA3WZBNDSUKA0GU_2026_05_22
#        BD0WIG2R2HTF3Q23UKHUYMRX61LF6QPZ8_2026_05_15
_RE_F3 = re.compile(
    r'^([A-Z]{2})[0-9A-Z]*[0-9][0-9A-Z]{9,}_\d{4}_\d{2}_\d{2}',
)
# Format 4 – HESOYAM : CC[GUID][DATE...]
#   Ex : AE[GS646EHVGWHFEUBDRI3QMXZFAKZ46BRMVL][2026-05-01
_RE_F4 = re.compile(
    r'^([A-Z]{2,4})\[',
    re.IGNORECASE,
)
# Format 5 – QLogs : INDEX_CC_IPv4_DD_MM_YYYY
#   Ex : 45265_IN_49.47.154.254_19_05_2026
_RE_F5 = re.compile(
    r'^\d+_([A-Z]{2,4})_(?:\d{1,3}\.){3}\d{1,3}',
    re.IGNORECASE,
)
# Format 6 – KIR3CLOUD / archives bracket : [CC - @SOURCE]_GUID ou [CC ]_desc
#   Ex : [AE - @KIR3CLOUD]_13wkkowy15idly5qe6k7rxcd  /  [AE ]_free (2)
_RE_F6 = re.compile(
    r'^\[([A-Z]{2,4})\b[^\]]*\]_',
    re.IGNORECASE,
)
# Format 7 – Vidar standalone : vidar_YYYYMMDD_CC_IP(.zip)
#   Ex : vidar_20260207_AO_154.127.162.101.zip
_RE_F7 = re.compile(
    r'^vidar_\d{8}_([A-Z]{2})_',
    re.IGNORECASE,
)

_VICTIM_PATTERNS = [_RE_F1, _RE_F2, _RE_F3, _RE_F4, _RE_F5, _RE_F6, _RE_F7]


def _match_victim_folder(part: str) -> str | None:
    """Retourne le code pays si `part` ressemble à un dossier victime, sinon None."""
    for pat in _VICTIM_PATTERNS:
        m = pat.match(part)
        if m:
            return m.group(1).upper()
    return None

# Catégories de données détectées au niveau 2 (sous-dossiers / fichiers directs)
_DATA_CATEGORIES: list[tuple[str, re.Pattern]] = [
    ("passwords",    re.compile(r'^passwords?(?:\..+)?$',           re.IGNORECASE)),
    ("cookies",      re.compile(r'^cookies?(?:\..+)?$',             re.IGNORECASE)),
    ("autofill",     re.compile(r'^autofill(?:\..+)?$',             re.IGNORECASE)),
    ("history",      re.compile(r'^history(?:\..+)?$',              re.IGNORECASE)),
    ("credit_cards", re.compile(r'^credit[\s_-]?cards?(?:\..+)?$',  re.IGNORECASE)),
    ("screenshots",  re.compile(r'^screenshots?(?:\..+)?$',         re.IGNORECASE)),
    ("downloads",    re.compile(r'^downloads?(?:\..+)?$',           re.IGNORECASE)),
    ("bookmarks",    re.compile(r'^bookmarks?(?:\..+)?$',           re.IGNORECASE)),
]

_ALL_CATS = [name for name, _ in _DATA_CATEGORIES]


def parse_country_structure(file_list: list[str]) -> dict:
    """
    Analyse une liste de chemins issus du contenu d'une archive.

    Cherche à TOUT niveau le premier composant de chemin qui ressemble à un
    dossier victime par pays (ex: FR_177.71.92.188_20.05.2026_15-58-34).
    Cela gère les archives avec un ou plusieurs dossiers racine intermédiaires
    (ex: @BRZCLOUD FREE LOGS 20.05.26/AE_.../Cookies/...).

    Retourne des statistiques agrégées par code pays :
    {
      "FR": { "total": 30, "with_passwords": 17, "with_cookies": 25 },
      "ES": { "total": 12, "with_passwords": 8 },
      "_total_victims": 42
    }
    Retourne {} si aucun dossier pays n'est détecté.
    """
    if not file_list:
        return {}

    # country → victim_folder_name → set of detected data categories
    victim_cats: dict[str, dict[str, set[str]]] = {}

    for path in file_list:
        norm  = path.replace("\\", "/").strip("/")
        parts = norm.split("/")
        # Cherche le premier composant qui ressemble à un dossier victime, à
        # n'importe quel niveau (y compris en dernière position pour les entrées
        # de répertoire comme "ROOT/AE_1.2.3.4_01.01.2026_00-00-00/").
        for i, part in enumerate(parts):
            country = _match_victim_folder(part)
            if country is None:
                continue
            victim_name  = part

            if country not in victim_cats:
                victim_cats[country] = {}
            if victim_name not in victim_cats[country]:
                victim_cats[country][victim_name] = set()

            # Le composant juste après = catégorie de données (Cookies, Passwords…)
            if i + 1 < len(parts) and parts[i + 1]:
                sub = parts[i + 1]
                for cat_name, cat_re in _DATA_CATEGORIES:
                    if cat_re.match(sub):
                        victim_cats[country][victim_name].add(cat_name)
            break  # un seul dossier pays par chemin

    # Agrégation par pays
    result: dict = {}
    total_victims = 0

    for country in sorted(victim_cats):
        folders = victim_cats[country]
        count   = len(folders)
        total_victims += count

        stats: dict = {"total": count}
        for cat in _ALL_CATS:
            n = sum(1 for cats in folders.values() if cat in cats)
            if n:
                stats[f"with_{cat}"] = n

        result[country] = stats

    result["_total_victims"] = total_victims
    return result
