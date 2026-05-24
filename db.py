"""
DataVortex – Couche base de données SQLite.
Stocke les archives ZIP/RAR et les patterns de détection de mots de passe.
"""

import json
import sqlite3
from pathlib import Path
from archive_utils import SEED_PATTERNS

DB_PATH = Path(__file__).parent / "datavortex.db"


# ── Connexion ─────────────────────────────────────────────────────────────────

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ── Initialisation ────────────────────────────────────────────────────────────

def init_db() -> None:
    """Crée les tables si elles n'existent pas encore et insère les patterns de base."""
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                archive_id   INTEGER NOT NULL REFERENCES archives(id) ON DELETE CASCADE,
                host         TEXT    NOT NULL,
                login        TEXT    NOT NULL DEFAULT '',
                password     TEXT    NOT NULL DEFAULT '',
                soft         TEXT    NOT NULL DEFAULT '',
                file_path    TEXT    NOT NULL DEFAULT '',
                found_at     TEXT    NOT NULL DEFAULT (datetime('now')),
                UNIQUE(archive_id, host, login)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS archives (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_id     INTEGER NOT NULL,
                channel_title  TEXT    NOT NULL,
                message_id     INTEGER NOT NULL,
                filename       TEXT    NOT NULL,
                extension      TEXT,
                file_size      TEXT,
                mime_type      TEXT,
                message_date   TEXT,
                is_encrypted   INTEGER,   -- 0 = non  |  1 = oui  |  NULL = inconnu
                password       TEXT,      -- mot de passe extrait du message
                message_text   TEXT,      -- caption/texte complet du message
                file_list      TEXT,      -- JSON : liste des fichiers dans l'archive
                folder_tree    TEXT,      -- JSON : arborescence groupée par code pays
                first_seen     TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(channel_id, message_id)
            )
        """)
        # Migration : ajoute file_list si la table existait déjà sans cette colonne
        try:
            conn.execute("ALTER TABLE archives ADD COLUMN file_list TEXT")
        except sqlite3.OperationalError:
            pass  # colonne déjà présente
        try:
            conn.execute("ALTER TABLE archives ADD COLUMN folder_tree TEXT")
        except sqlite3.OperationalError:
            pass  # colonne déjà présente
        conn.execute("""
            CREATE TABLE IF NOT EXISTS patterns (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern     TEXT    NOT NULL UNIQUE,
                description TEXT    NOT NULL DEFAULT '',
                source      TEXT    NOT NULL DEFAULT 'seed',  -- seed | auto | manual
                match_count INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
            )
        """)
        # Migration : ajoute la table credentials si elle n'existe pas encore
        conn.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                archive_id   INTEGER NOT NULL,
                host         TEXT    NOT NULL,
                login        TEXT    NOT NULL DEFAULT '',
                password     TEXT    NOT NULL DEFAULT '',
                soft         TEXT    NOT NULL DEFAULT '',
                file_path    TEXT    NOT NULL DEFAULT '',
                found_at     TEXT    NOT NULL DEFAULT (datetime('now')),
                UNIQUE(archive_id, host, login)
            )
        """)
        conn.commit()
    _seed_patterns()


def _seed_patterns() -> None:
    """Insère les patterns de base s'ils ne sont pas encore en base."""
    with get_connection() as conn:
        for pattern, description in SEED_PATTERNS:
            conn.execute(
                "INSERT OR IGNORE INTO patterns (pattern, description, source) VALUES (?, ?, 'seed')",
                (pattern, description),
            )
        conn.commit()


# ── Écriture ──────────────────────────────────────────────────────────────────

def upsert_archive(
    channel_id: int,
    channel_title: str,
    message_id: int,
    filename: str,
    extension: str,
    file_size: str | None,
    mime_type: str | None,
    message_date: str | None,
    is_encrypted: bool | None,
    password: str | None,
    message_text: str | None,
    file_list: list[str] | None = None,
    folder_tree: dict | None = None,
) -> bool:
    """
    Insère une nouvelle archive ou met à jour une entrée existante
    (identifiée par channel_id + message_id).

    Retourne True si c'était une nouvelle entrée, False si mise à jour.
    """
    enc_val        = None if is_encrypted is None else (1 if is_encrypted else 0)
    file_list_js   = json.dumps(file_list, ensure_ascii=False) if file_list else None
    folder_tree_js = json.dumps(folder_tree, ensure_ascii=False) if folder_tree else None

    with get_connection() as conn:
        existing = conn.execute(
            "SELECT id FROM archives WHERE channel_id = ? AND message_id = ?",
            (channel_id, message_id),
        ).fetchone()

        if existing:
            conn.execute(
                """
                UPDATE archives
                SET channel_title = ?, filename = ?, extension = ?, file_size = ?,
                    mime_type = ?, message_date = ?, is_encrypted = ?,
                    password = ?, message_text = ?, file_list = ?, folder_tree = ?
                WHERE channel_id = ? AND message_id = ?
                """,
                (
                    channel_title, filename, extension, file_size,
                    mime_type, message_date, enc_val,
                    password, message_text, file_list_js, folder_tree_js,
                    channel_id, message_id,
                ),
            )
            conn.commit()
            return False

        conn.execute(
            """
            INSERT INTO archives
                (channel_id, channel_title, message_id, filename, extension,
                 file_size, mime_type, message_date, is_encrypted, password, message_text,
                 file_list, folder_tree)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                channel_id, channel_title, message_id, filename, extension,
                file_size, mime_type, message_date, enc_val, password, message_text,
                file_list_js, folder_tree_js,
            ),
        )
        conn.commit()
        return True


# ── Lecture ───────────────────────────────────────────────────────────────────

def get_archive_id(channel_id: int, message_id: int) -> int | None:
    """Retourne l'id DB d'une archive, ou None si elle n'existe pas encore."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id FROM archives WHERE channel_id = ? AND message_id = ?",
            (channel_id, message_id),
        ).fetchone()
    return row["id"] if row else None


def save_credentials(archive_id: int, creds: list[dict]) -> int:
    """
    Insère les credentials trouvés pour une archive.
    Ignore les doublons (UNIQUE archive_id + host + login).
    Retourne le nombre de nouvelles entrées insérées.
    """
    if not creds or not archive_id:
        return 0
    inserted = 0
    with get_connection() as conn:
        for c in creds:
            try:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO credentials
                        (archive_id, host, login, password, soft, file_path)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        archive_id,
                        c.get("host", ""),
                        c.get("login", ""),
                        c.get("password", ""),
                        c.get("soft", ""),
                        c.get("file_path", ""),
                    ),
                )
                inserted += conn.execute("SELECT changes()").fetchone()[0]
            except Exception:
                continue
        conn.commit()
    return inserted


def search_credentials_db(
    target: str | None = None,
    limit: int = 500,
) -> list[sqlite3.Row]:
    """
    Cherche des credentials en DB.
    Si `target` est fourni, filtre sur les hosts contenant cette chaîne.
    Retourne les lignes triées par host puis login.
    """
    with get_connection() as conn:
        if target:
            return conn.execute(
                """
                SELECT c.*, a.filename, a.channel_title, a.message_date
                FROM credentials c
                JOIN archives a ON a.id = c.archive_id
                WHERE LOWER(c.host) LIKE ?
                ORDER BY c.host, c.login
                LIMIT ?
                """,
                (f"%{target.lower()}%", limit),
            ).fetchall()
        return conn.execute(
            """
            SELECT c.*, a.filename, a.channel_title, a.message_date
            FROM credentials c
            JOIN archives a ON a.id = c.archive_id
            ORDER BY c.host, c.login
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def get_all_archives(with_password_only: bool = False) -> list[sqlite3.Row]:
    """Retourne toutes les archives enregistrées, triées par channel puis date."""
    with get_connection() as conn:
        if with_password_only:
            return conn.execute(
                "SELECT * FROM archives WHERE password IS NOT NULL ORDER BY message_date DESC"
            ).fetchall()
        return conn.execute(
            "SELECT * FROM archives ORDER BY channel_title, message_date DESC"
        ).fetchall()


def get_stats() -> dict:
    """Retourne des statistiques globales sur la base."""
    with get_connection() as conn:
        total      = conn.execute("SELECT COUNT(*) FROM archives").fetchone()[0]
        encrypted  = conn.execute("SELECT COUNT(*) FROM archives WHERE is_encrypted = 1").fetchone()[0]
        no_enc     = conn.execute("SELECT COUNT(*) FROM archives WHERE is_encrypted = 0").fetchone()[0]
        unknown    = conn.execute("SELECT COUNT(*) FROM archives WHERE is_encrypted IS NULL").fetchone()[0]
        with_pwd   = conn.execute("SELECT COUNT(*) FROM archives WHERE password IS NOT NULL").fetchone()[0]
        by_channel = conn.execute(
            """
            SELECT channel_title, COUNT(*) AS cnt
            FROM archives
            GROUP BY channel_id
            ORDER BY cnt DESC
            """
        ).fetchall()

    return {
        "total": total,
        "encrypted": encrypted,
        "not_encrypted": no_enc,
        "unknown": unknown,
        "with_password": with_pwd,
        "by_channel": [(r["channel_title"], r["cnt"]) for r in by_channel],
    }


# ── Patterns ──────────────────────────────────────────────────────────────────

def load_patterns() -> list[str]:
    """Charge tous les patterns depuis la DB, triés par utilité décroissante."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT pattern FROM patterns ORDER BY match_count DESC, id ASC"
        ).fetchall()
    return [r["pattern"] for r in rows]


def add_pattern(pattern: str, description: str = "", source: str = "auto") -> bool:
    """
    Ajoute un nouveau pattern en base.
    Retourne True si ajouté, False s'il existait déjà.
    """
    with get_connection() as conn:
        try:
            conn.execute(
                "INSERT INTO patterns (pattern, description, source) VALUES (?, ?, ?)",
                (pattern, description, source),
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False


def increment_pattern_match(pattern_str: str) -> None:
    """Incrémente le compteur d'utilisation d'un pattern."""
    with get_connection() as conn:
        conn.execute(
            "UPDATE patterns SET match_count = match_count + 1 WHERE pattern = ?",
            (pattern_str,),
        )
        conn.commit()


def get_all_patterns() -> list[sqlite3.Row]:
    """Retourne tous les patterns enregistrés."""
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM patterns ORDER BY match_count DESC, id ASC"
        ).fetchall()
