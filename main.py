"""
DataVortex – Telegram Archive Scanner
Pipeline automatique : connexion → channels → scan → résultats → DB.
"""

import json
import os
import asyncio
import tempfile
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

from rich.console import Console
from rich.table import Table
from rich.rule import Rule
from rich.text import Text
from rich import box
from rich.progress import (
    Progress, BarColumn, DownloadColumn,
    TransferSpeedColumn, TimeRemainingColumn,
)

from telethon import TelegramClient
from telethon.tl.types import (
    Channel, Chat,
    MessageMediaDocument,
    Document,
    DocumentAttributeFilename,
)

from archive_utils import (
    is_archive, detect_encryption,
    extract_password, auto_discover_pattern, compile_patterns,
    list_local_archive, parse_country_structure,
)
from credential_search import search_credentials
from groq_utils import ask_groq_structure, ask_groq_password, key_available
from db import (
    init_db, load_patterns, add_pattern, increment_pattern_match,
    upsert_archive, get_all_archives, get_stats, get_all_patterns,
    get_archive_id, save_credentials, search_credentials_db,
)

load_dotenv()

API_ID       = int(os.environ["API_ID"])
API_HASH     = os.environ["API_HASH"]
PHONE        = os.environ["PHONE"]
SESSION_NAME = os.environ.get("SESSION_NAME", "datavortex_session")
SCAN_LIMIT   = int(os.environ.get("SCAN_LIMIT", "200"))
# Domaines à rechercher dans les fichiers passwords (séparés par des virgules dans .env)
CREDENTIAL_TARGETS: list[str] = [
    t.strip() for t in os.environ.get("CREDENTIAL_TARGETS", "").split(",") if t.strip()
]

HEADER_BYTES = 4096       # octets lus localement pour détection du chiffrement
DAYS_LIMIT   = 5         # on ne traite que les archives uploadées dans les DAYS_LIMIT derniers jours
TEMP_DIR     = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_downloads")
os.makedirs(TEMP_DIR, exist_ok=True)

console = Console()


# ── Palette de couleurs ───────────────────────────────────────────────────────

C_LOCKED    = "bold red"
C_UNLOCKED  = "bold green"
C_UNKNOWN   = "bold yellow"
C_PASSWORD  = "bold cyan"
C_NEW       = "bright_green"
C_CHANNEL   = "bold blue"
C_DISCOVER  = "bold magenta"
C_DIM       = "dim"
C_TITLE     = "bold white"


def enc_badge(is_enc: bool | None) -> Text:
    if is_enc is True:
        return Text("🔒 OUI", style=C_LOCKED)
    if is_enc is False:
        return Text("🔓 NON", style=C_UNLOCKED)
    return Text("❓  ?  ", style=C_UNKNOWN)


# ── Telegram ──────────────────────────────────────────────────────────────────

async def download_header(client: TelegramClient, media) -> bytes:
    chunks: list[bytes] = []
    total = 0
    try:
        async for chunk in client.iter_download(media, request_size=HEADER_BYTES):
            chunks.append(bytes(chunk))
            total += len(chunks[-1])
            if total >= HEADER_BYTES:
                break
    except Exception:
        pass
    return b"".join(chunks)[:HEADER_BYTES]


async def download_tail(client: TelegramClient, media, file_size: int) -> tuple[bytes, int]:
    """
    Télécharge les derniers TAIL_BYTES octets du fichier pour lire le répertoire
    central ZIP. Retourne (données, offset_de_début).
    Si le fichier est plus petit que TAIL_BYTES, retourne (b"", 0) car les
    données de début couvrent déjà tout le fichier.
    """
    if file_size <= TAIL_BYTES:
        return b"", 0
    # Telegram exige un offset multiple de 4096
    offset = ((file_size - TAIL_BYTES) // 4096) * 4096
    # L'alignement vers le bas déplace le début en-deçà de (file_size - TAIL_BYTES).
    # On doit donc télécharger file_size - offset octets (légèrement > TAIL_BYTES)
    # pour couvrir réellement la fin du fichier où se trouve l'EOCD.
    need = file_size - offset
    chunks: list[bytes] = []
    total = 0
    try:
        async for chunk in client.iter_download(media, offset=offset, request_size=TAIL_BYTES):
            chunks.append(bytes(chunk))
            total += len(chunks[-1])
            if total >= need:
                break
    except Exception:
        return b"", 0
    return b"".join(chunks)[:need], offset


async def download_exact(client: TelegramClient, media, offset: int, size: int) -> bytes:
    """
    Télécharge exactement `size` octets à partir de `offset` absolu.
    Aligne l'offset sur 4096 en interne (contrainte Telegram).
    Retourne b"" en cas d'échec.
    """
    aligned = (offset // 4096) * 4096
    extra   = offset - aligned
    # Utilise des chunks de 512 Ko (limite sûre Telegram) pour éviter les
    # rejets silencieux quand size dépasse la capacité d'un seul GetFile.
    CHUNK = 524_288
    chunks: list[bytes] = []
    total = 0
    need  = extra + size
    try:
        async for chunk in client.iter_download(media, offset=aligned, request_size=CHUNK):
            chunks.append(bytes(chunk))
            total += len(chunks[-1])
            if total >= need:
                break
    except Exception as exc:
        console.print(f"      [{C_DIM}]⚠ download_exact échoué (offset={offset:,}, size={size:,}): {exc}[/]")
        return b""
    raw = b"".join(chunks)
    got = raw[extra : extra + size]
    if len(got) < size:
        console.print(f"      [{C_DIM}]⚠ download_exact incomplet: reçu {len(got):,}/{size:,} bytes[/]")
    return got


async def download_rar_listing(client: TelegramClient, media) -> bytes:
    """
    Télécharge les premiers RAR_LISTING_BYTES du fichier pour parcourir
    un maximum de file headers RAR et détecter les dossiers victimes.
    Le listing sera toujours partiel sur de grandes archives.
    """
    chunks: list[bytes] = []
    total = 0
    try:
        async for chunk in client.iter_download(media, request_size=RAR_LISTING_BYTES):
            chunks.append(bytes(chunk))
            total += len(chunks[-1])
            if total >= RAR_LISTING_BYTES:
                break
    except Exception:
        pass
    return b"".join(chunks)[:RAR_LISTING_BYTES]


async def fetch_channels(client: TelegramClient) -> list[dict]:
    channels = []
    async for dialog in client.iter_dialogs():
        entity = dialog.entity
        if isinstance(entity, (Channel, Chat)):
            channels.append({
                "id": entity.id,
                "title": dialog.title,
                "unread": dialog.unread_count,
                "type": "Canal" if getattr(entity, "broadcast", False) else "Groupe",
            })
    return channels


DOWNLOAD_WORKERS  = int(os.environ.get("DOWNLOAD_WORKERS", "4"))
DOWNLOAD_CHUNK_KB = int(os.environ.get("DOWNLOAD_CHUNK_KB", "512"))


async def _parallel_download(
    client: TelegramClient,
    message,
    path: str,
    workers: int = DOWNLOAD_WORKERS,
    chunk_size: int = DOWNLOAD_CHUNK_KB * 1024,
    progress_cb=None,
) -> None:
    """Téléchargement parallèle via iter_download + stride pour maximiser le débit."""
    size   = message.document.size
    stride = workers * chunk_size
    downloaded = 0
    lock = asyncio.Lock()

    # Pré-alloue le fichier sur disque
    with open(path, "wb") as _fh:
        _fh.truncate(size)

    fh = open(path, "r+b")
    try:
        async def _worker(wid: int) -> None:
            nonlocal downloaded
            pos = wid * chunk_size
            async for chunk in client.iter_download(
                message,
                offset=wid * chunk_size,
                stride=stride,
                chunk_size=chunk_size,
                file_size=size,
            ):
                async with lock:
                    fh.seek(pos)
                    fh.write(chunk)
                    downloaded += len(chunk)
                    if progress_cb:
                        progress_cb(min(downloaded, size), size)
                pos += stride

        await asyncio.gather(*[_worker(i) for i in range(workers)])
    finally:
        fh.close()


async def scan_channel(
    client: TelegramClient,
    channel_id: int,
    channel_title: str,
    pattern_strs: list[str],
    compiled: list,
) -> tuple[int, int]:
    """
    Scanne un channel pour les archives ZIP/RAR.
    Met à jour pattern_strs et compiled en place si un nouveau pattern est découvert.
    Retourne (nb_trouvées, nb_nouvelles_en_db).
    """
    found = new_entries = 0

    async for message in client.iter_messages(channel_id, limit=SCAN_LIMIT):
        if not isinstance(message.media, MessageMediaDocument):
            continue

        doc = message.media.document
        if not isinstance(doc, Document):
            continue

        filename: str | None = None
        for attr in doc.attributes:
            if isinstance(attr, DocumentAttributeFilename):
                filename = attr.file_name
                break

        if not filename:
            continue

        mime = doc.mime_type or ""
        if not is_archive(filename, mime):
            continue

        found += 1
        ext       = os.path.splitext(filename.lower())[1]
        file_size = _fmt_size(doc.size) if doc.size else None
        msg_date  = message.date.strftime("%Y-%m-%d %H:%M") if message.date else None
        msg_text  = message.message or None

        # ── Filtre par date : archives > DAYS_LIMIT jours ignorées ─────────
        if message.date and (datetime.now(timezone.utc) - message.date) > timedelta(days=DAYS_LIMIT):
            break  # iter_messages renvoie du plus récent au plus ancien

        # ── Téléchargement complet de l'archive ───────────────────────────
        temp_path = os.path.join(TEMP_DIR, f"dv_{channel_id}_{message.id}{ext}")
        console.print(f"      [{C_DIM}]📥 Téléchargement ({file_size or '?'}) …[/]")
        try:
            with Progress(
                "[progress.description]{task.description}",
                BarColumn(bar_width=20),
                "[progress.percentage]{task.percentage:>3.0f}%",
                DownloadColumn(),
                TransferSpeedColumn(),
                TimeRemainingColumn(),
                console=console,
                transient=True,
            ) as _prog:
                _task = _prog.add_task("", total=doc.size or None)
                def _dl_cb(current, total, _t=_task, _p=_prog):
                    _p.update(_t, completed=current)
                await _parallel_download(client, message, temp_path, progress_cb=_dl_cb)
        except Exception as exc:
            console.print(f"      [{C_DIM}]⚠ Téléchargement échoué : {exc}[/]")
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            continue

        # ── Analyse locale ────────────────────────────────────────────────
        is_enc        = None
        file_list     = None
        folder_tree   = None
        is_rar_partial = False
        creds_found: list[dict] = []
        try:
            with open(temp_path, "rb") as _fh:
                _hdr = _fh.read(HEADER_BYTES)
            is_enc = detect_encryption(_hdr, filename) if _hdr else None
            file_list   = list_local_archive(temp_path, filename)
            folder_tree = parse_country_structure(file_list) if file_list else None
            if file_list is None:
                if is_enc is not True:
                    console.print(f"      [{C_DIM}]⚠ listing: IMPOSSIBLE (chiffrement global ou format non reconnu)[/]")
            elif file_list == []:
                console.print(f"      [{C_DIM}]⚠ listing: archive vide[/]")
            else:
                has_victims = any(not k.startswith("_") for k in (folder_tree or {}))
                if not has_victims:
                    preview = ", ".join(file_list[:3])
                    console.print(f"      [{C_DIM}]⚠ structure: arborescence victime non reconnue — ex: {preview}[/]")
                    groq_tree = await ask_groq_structure(file_list)
                    if groq_tree:
                        folder_tree = groq_tree
                        conf     = groq_tree.get("_groq_confidence", "?")
                        total_g  = groq_tree.get("_total_victims", 0)
                        cc_parts = [
                            f"{cc}:{v['total']}"
                            for cc, v in list(groq_tree.items())[:6]
                            if not str(cc).startswith("_")
                        ]
                        console.print(
                            f"      [{C_DIM}]🤖 Groq: {total_g} victimes "
                            f"({conf}) — {', '.join(cc_parts)}[/]"
                        )
                    elif key_available():
                        console.print(f"      [{C_DIM}]🤖 Groq: aucune structure identifiée[/]")
            # ── Recherche de credentials ciblés (fichiers passwords) ─────────
            if CREDENTIAL_TARGETS and file_list is not None:
                creds_found = search_credentials(temp_path, filename, CREDENTIAL_TARGETS)
                if creds_found:
                    console.print(
                        f"      [{C_PASSWORD}]🔑 {len(creds_found)} credential(s) trouvé(s) :[/]"
                    )
                    for _c in creds_found[:10]:
                        _h = (_c['host'])[:70]
                        _l = _c['login'] or '—'
                        _p = _c['password'] or '—'
                        console.print(f"         [{C_DIM}]{_h}  {_l} : {_p}[/]")
                    if len(creds_found) > 10:
                        console.print(f"         [{C_DIM}]  … +{len(creds_found) - 10} autres[/]")
        finally:
            try:
                os.unlink(temp_path)
            except OSError:
                pass

        # ── Extraction du mot de passe ────────────────────────────────────
        password, matched_pattern = extract_password(msg_text, compiled)

        if matched_pattern:
            increment_pattern_match(matched_pattern)

        # ── Auto-découverte si aucun pattern n'a matché ───────────────────
        elif msg_text:
            discovered = auto_discover_pattern(msg_text, pattern_strs)
            if discovered:
                new_pat, password = discovered
                if add_pattern(new_pat, description="Auto-découvert", source="auto"):
                    pattern_strs.append(new_pat)
                    compiled.extend(compile_patterns([new_pat]))
                    console.print(
                        f"      [{ C_DISCOVER}]✦ Nouveau pattern découvert :[/] "
                        f"[{C_DIM}]{new_pat[:60]}[/]"
                    )
            else:
                # Aucun pattern ne correspond au texte du message
                # Avertissement seulement pour les archives chiffrées (mot de passe nécessaire)
                if is_enc is True:
                    txt_preview = msg_text[:100].replace("\n", " ")
                    console.print(f"      [{C_DIM}]⚠ mdp: INTROUVABLE — texte: {txt_preview!r}[/]")
                    # Fallback Groq : NLP pour extraire le mot de passe
                    groq_pwd = await ask_groq_password(msg_text)
                    if groq_pwd:
                        password = groq_pwd
                        console.print(f"      [{C_DIM}]🤖 Groq mdp: {password!r}[/]")
                    elif key_available():
                        console.print(f"      [{C_DIM}]🤖 Groq: aucun mot de passe détecté[/]")
        elif not msg_text and is_enc is True:
            console.print(f"      [{C_DIM}]⚠ mdp: INTROUVABLE — aucun texte dans le message[/]")

        # ── Sauvegarde en DB ──────────────────────────────────────────────
        is_new = upsert_archive(
            channel_id=channel_id,
            channel_title=channel_title,
            message_id=message.id,
            filename=filename,
            extension=ext,
            file_size=file_size,
            mime_type=mime,
            message_date=msg_date,
            is_encrypted=is_enc,
            password=password,
            message_text=msg_text,
            file_list=file_list,
            folder_tree=folder_tree,
        )
        if is_new:
            new_entries += 1

        # Sauvegarde des credentials trouvés
        if creds_found:
            _aid = get_archive_id(channel_id, message.id)
            if _aid:
                save_credentials(_aid, creds_found)

        # ── Affichage temps réel ──────────────────────────────────────────
        badge    = enc_badge(is_enc)
        new_tag  = Text(" [NEW]", style=C_NEW) if is_new else Text("")
        pwd_part = Text(f"  mdp={password}", style=C_PASSWORD) if password else Text("")
        date_str = f"[{msg_date}] " if msg_date else ""
        size_str = f" ({file_size})" if file_size else ""

        line = Text("    ")
        line.append(date_str, style=C_DIM)
        line.append_text(badge)
        line.append(f" {filename}{size_str}")
        line.append_text(pwd_part)
        line.append_text(new_tag)
        console.print(line)

        # Prévisualisation du contenu
        if folder_tree and folder_tree.get("_total_victims", 0) > 0:
            total_v   = folder_tree.get("_total_victims", 0)
            countries = {k: v for k, v in folder_tree.items() if not k.startswith("_")}
            prefix    = "≥" if is_rar_partial else ""
            parts_cc  = []
            for cc, stats in list(countries.items())[:6]:
                detail = []
                if stats.get("with_passwords"): detail.append(f"mdp:{stats['with_passwords']}")
                if stats.get("with_cookies"):   detail.append(f"ck:{stats['with_cookies']}")
                if stats.get("with_autofill"):  detail.append(f"af:{stats['with_autofill']}")
                suffix = f"({', '.join(detail)})" if detail else ""
                parts_cc.append(f"{cc}:{stats['total']}{suffix}")
            summary = "  ".join(parts_cc)
            extra   = f"  (+{len(countries) - 6} pays)" if len(countries) > 6 else ""
            console.print(f"         [{C_DIM}]🌍 {prefix}{total_v} victimes — {summary}{extra}[/]")
        elif file_list:
            files_only = [f for f in file_list if not f.endswith("/")]
            preview = ", ".join(files_only[:3])
            if len(files_only) > 3:
                preview += f" … (+{len(files_only) - 3} fichiers)"
            console.print(f"         [{C_DIM}]📁 {preview}[/]")

    return found, new_entries


# ── Affichage des résultats ───────────────────────────────────────────────────

def _fmt_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / 1024 ** 2:.1f} MB"
    return f"{size_bytes / 1024 ** 3:.2f} GB"


def show_archives_table(rows: list, title: str) -> None:
    if not rows:
        console.print(f"  [{C_DIM}]Aucune entrée.[/]")
        return

    table = Table(
        title=title,
        box=box.ROUNDED,
        show_lines=False,
        title_style=C_TITLE,
        header_style="bold white on dark_blue",
        border_style="blue",
    )
    table.add_column("Date",       style="white",      width=17)
    table.add_column("Chiffré",    justify="center",   width=8)
    table.add_column("Fichier",    style="white",      max_width=42)
    table.add_column("Taille",     style=C_DIM,        width=9)
    table.add_column("Contenu",    style=C_DIM,        max_width=35)
    table.add_column("Mot de passe", style=C_PASSWORD, max_width=24)
    table.add_column("Channel",    style=C_CHANNEL,    max_width=30)

    for r in rows:
        enc_val = r["is_encrypted"]
        if enc_val == 1:
            enc_cell = Text("🔒 OUI", style=C_LOCKED)
        elif enc_val == 0:
            enc_cell = Text("🔓 NON", style=C_UNLOCKED)
        else:
            enc_cell = Text("❓  ? ", style=C_UNKNOWN)

        # Prévisualisation du contenu de l'archive
        raw_ft = r["folder_tree"] if "folder_tree" in r.keys() else None
        raw_fl = r["file_list"]   if "file_list"   in r.keys() else None
        if raw_ft:
            ft       = json.loads(raw_ft)
            total_v  = ft.get("_total_victims", 0)
            countries = {k: v for k, v in ft.items() if not k.startswith("_")}
            parts_cc = []
            for cc, stats in list(countries.items())[:5]:
                parts_cc.append(f"{cc}:{stats['total']}")
            suffix = "  ".join(parts_cc)
            if len(countries) > 5:
                suffix += f" +{len(countries)-5}"
            content_cell = f"{total_v}v — {suffix}" if total_v else suffix
        elif raw_fl:
            fl = json.loads(raw_fl)
            files_only = [f for f in fl if not f.endswith("/")]
            preview = ", ".join(files_only[:3])
            if len(files_only) > 3:
                preview += f" … (+{len(files_only) - 3})"
            content_cell = preview
        else:
            content_cell = ""

        table.add_row(
            r["message_date"] or "?",
            enc_cell,
            r["filename"],
            r["file_size"] or "?",
            content_cell,
            r["password"] or "",
            r["channel_title"],
        )

    console.print(table)


def show_patterns_table() -> None:
    rows = get_all_patterns()
    table = Table(
        title="Patterns actifs",
        box=box.SIMPLE_HEAVY,
        title_style=C_TITLE,
        header_style="bold white on dark_blue",
        border_style="magenta",
    )
    table.add_column("Source",    width=8)
    table.add_column("Utilisations", justify="right", width=10)
    table.add_column("Pattern",   max_width=60)
    table.add_column("Description", max_width=30, style=C_DIM)

    source_colors = {"seed": "cyan", "auto": C_DISCOVER, "manual": "green"}

    for r in rows:
        src_color = source_colors.get(r["source"], "white")
        table.add_row(
            Text(r["source"], style=src_color),
            str(r["match_count"]),
            Text(r["pattern"][:58], style=C_DIM),
            r["description"] or "",
        )
    console.print(table)


def show_stats() -> None:
    stats = get_stats()
    console.print()
    console.print(f"  [{C_TITLE}]Total archives      :[/]  {stats['total']}")
    console.print(f"  [{C_LOCKED}]Protégées    🔒    :[/]  {stats['encrypted']}")
    console.print(f"  [{C_UNLOCKED}]Non protégées 🔓   :[/]  {stats['not_encrypted']}")
    console.print(f"  [{C_UNKNOWN}]Statut inconnu ❓  :[/]  {stats['unknown']}")
    console.print(f"  [{C_PASSWORD}]Mot de passe connu :[/]  {stats['with_password']}")
    if stats["by_channel"]:
        console.print()
        console.print(f"  [{C_TITLE}]Par channel :[/]")
        for title, cnt in stats["by_channel"]:
            console.print(f"    [{C_CHANNEL}]{cnt:>5}[/]  {title}")


# ── Pipeline principal ────────────────────────────────────────────────────────

async def main() -> None:
    init_db()

    # Charger les patterns depuis la DB (seeds + auto-découverts + manuels)
    pattern_strs = load_patterns()
    compiled     = compile_patterns(pattern_strs)

    # ── Étape 1 : Connexion ───────────────────────────────────────────────────
    console.rule(f"[{C_TITLE}] DATAVORTEX [/]", style="blue")
    client = TelegramClient(SESSION_NAME, API_ID, API_HASH)
    await client.start(phone=PHONE)  # type: ignore[misc]
    me    = await client.get_me()
    name  = getattr(me, "first_name", "") or ""
    uname = getattr(me, "username", None)
    console.print(
        f"  [bold green]✓[/] Connecté : [{C_TITLE}]{name}[/]"
        + (f" [{C_DIM}](@{uname})[/]" if uname else "")
    )
    console.print(
        f"  [{C_DIM}]{len(pattern_strs)} pattern(s) de détection chargé(s)[/]"
    )
    if key_available():
        console.print(f"  [{C_DIM}]🤖 Groq: clé présente — fallback IA activé (structure + mdp)[/]")
    else:
        console.print(f"  [yellow]🤖 Groq: GROQ_API_KEY absent — fallback IA désactivé (ajoutez-le dans .env)[/]")

    # ── Étape 2 : Liste des channels ──────────────────────────────────────────
    console.rule(f"[{C_CHANNEL}]CHANNELS DU COMPTE[/]", style="blue")
    channels = await fetch_channels(client)

    ch_table = Table(box=box.SIMPLE, show_header=True, header_style="bold white on dark_blue")
    ch_table.add_column("#",       justify="right", width=4)
    ch_table.add_column("Type",    width=7)
    ch_table.add_column("Nom",     style=C_CHANNEL, max_width=50)
    ch_table.add_column("Non lus", justify="right", width=8)

    for i, ch in enumerate(channels, 1):
        unread = str(ch["unread"]) if ch["unread"] else ""
        type_color = "cyan" if ch["type"] == "Canal" else "yellow"
        ch_table.add_row(
            str(i),
            Text(ch["type"], style=type_color),
            ch["title"],
            Text(unread, style="bold red") if unread else "",
        )
    console.print(ch_table)

    # ── Étape 3 : Scan de tous les channels ───────────────────────────────────
    console.rule(
        f"[{C_TITLE}]SCAN DES ARCHIVES ZIP/RAR[/] "
        f"[{C_DIM}]({SCAN_LIMIT} messages/channel)[/]",
        style="blue",
    )

    total_found = total_new = 0
    for ch in channels:
        console.print(f"\n  [{C_CHANNEL}]▶[/] [{C_TITLE}]{ch['title']}[/]")
        found, new = await scan_channel(
            client, ch["id"], ch["title"], pattern_strs, compiled
        )
        total_found += found
        total_new   += new
        if found:
            console.print(
                f"  [{C_DIM}]└ {found} archive(s) |[/] "
                f"[{C_NEW}]{new} nouvelle(s)[/]"
            )

    console.print()
    console.print(
        f"  [{C_TITLE}]Scan terminé :[/] [{C_NEW}]{total_found}[/] archive(s) trouvée(s), "
        f"[{C_NEW}]{total_new}[/] nouvelle(s) en base."
    )

    # ── Étape 4 : Archives avec mot de passe (flags) ──────────────────────────
    console.rule(f"[{C_PASSWORD}]ARCHIVES AVEC MOT DE PASSE DÉTECTÉ[/]", style="cyan")
    pwd_rows = get_all_archives(with_password_only=True)
    show_archives_table(pwd_rows, "Archives protégées – mot de passe connu")

    # ── Étape 5 : Base de données complète ────────────────────────────────────
    console.rule(f"[{C_TITLE}]BASE DE DONNÉES COMPLÈTE[/]", style="blue")
    all_rows = get_all_archives(with_password_only=False)
    show_archives_table(all_rows, f"Toutes les archives ({len(all_rows)} entrées)")

    # ── Étape 6 : Patterns actifs ─────────────────────────────────────────────
    console.rule(f"[{C_DISCOVER}]PATTERNS DE DÉTECTION[/]", style="magenta")
    show_patterns_table()

    # ── Stats ─────────────────────────────────────────────────────────────────
    console.rule(style="blue")
    show_stats()

    await client.disconnect()  # type: ignore[misc]
    console.print()
    console.rule(f"[{C_DIM}]Déconnexion — À bientôt ![/]", style="dim")


if __name__ == "__main__":
    asyncio.run(main())
