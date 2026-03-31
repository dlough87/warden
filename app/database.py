import aiosqlite
import json
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = "/data/warden.db"

DEFAULT_SETTINGS = {
    "dry_run": "true",
    "watch_threshold_percent": "80",
    "tv_watched_definition": "any_episode",
    "death_row_days": "30",
    "expedite_days": "",
    "schedule": "0 8 * * *",
    "timezone": "UTC",
    "radarr_url": "",
    "radarr_api_key": "",
    "radarr_public_url": "",
    "sonarr_url": "",
    "sonarr_api_key": "",
    "sonarr_public_url": "",
    "plex_url": "",
    "plex_token": "",
    "plex_public_url": "",
    "tautulli_url": "",
    "tautulli_api_key": "",
    "tautulli_public_url": "",
    "plex_machine_id": "",
    "webauthn_rp_id": "",
}

DEFAULT_RULES = [
    {
        "name": "Never Watched",
        "media_type": "both",
        "enabled": 1,
        "added_months": 18,
        "unwatched_months": None,
        "max_rating": None,
        "min_rating": None,
        "max_plays": None,
        "min_size_gb": None,
        "exclude_genres": None,
        "sort_order": 0,
    },
    {
        "name": "Old & Low Rated",
        "media_type": "both",
        "enabled": 1,
        "added_months": 60,
        "unwatched_months": 18,
        "max_rating": 7.0,
        "min_rating": None,
        "max_plays": None,
        "min_size_gb": None,
        "exclude_genres": None,
        "sort_order": 1,
    },
    {
        "name": "Very Old",
        "media_type": "both",
        "enabled": 1,
        "added_months": 96,
        "unwatched_months": 60,
        "max_rating": 8.0,
        "min_rating": None,
        "max_plays": None,
        "min_size_gb": None,
        "exclude_genres": None,
        "sort_order": 2,
    },
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS rules (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT NOT NULL,
    media_type     TEXT DEFAULT 'both',
    enabled        INTEGER DEFAULT 1,
    added_months   INTEGER,
    unwatched_months INTEGER,
    max_rating     REAL,
    min_rating     REAL,
    max_plays      INTEGER,
    min_size_gb    REAL,
    exclude_genres TEXT,
    include_genres TEXT,
    sort_order     INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS media_items (
    id                TEXT PRIMARY KEY,
    media_type        TEXT NOT NULL,
    arr_id            INTEGER NOT NULL,
    title             TEXT NOT NULL,
    year              INTEGER,
    imdb_rating       REAL,
    genres            TEXT,
    added_date        TEXT,
    last_watched_date TEXT,
    max_watch_percent REAL,
    total_plays       INTEGER DEFAULT 0,
    size_bytes        INTEGER,
    criteria_matched  TEXT,
    status            TEXT DEFAULT 'ok',
    death_row_date    TEXT,
    condemned_date    TEXT,
    pardon_reason     TEXT,
    updated_at        TEXT
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at        TEXT,
    completed_at      TEXT,
    dry_run           INTEGER,
    new_candidates    INTEGER DEFAULT 0,
    condemned_count   INTEGER DEFAULT 0,
    deleted_count     INTEGER DEFAULT 0,
    space_freed_bytes INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS notification_agents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    agent_type  TEXT NOT NULL,
    enabled     INTEGER DEFAULT 1,
    config      TEXT NOT NULL DEFAULT '{}',
    events      TEXT NOT NULL DEFAULT '[]',
    created_at  TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    action    TEXT NOT NULL,
    detail    TEXT,
    ip        TEXT
);

CREATE TABLE IF NOT EXISTS passkeys (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_id BLOB NOT NULL UNIQUE,
    public_key    BLOB NOT NULL,
    sign_count    INTEGER NOT NULL DEFAULT 0,
    name          TEXT NOT NULL DEFAULT 'Passkey',
    created_at    TEXT NOT NULL
);
"""


async def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.executescript(SCHEMA)
        await _seed_settings(db)
        await _seed_rules(db)
        # Migrations — safe to run on every boot (ADD COLUMN is a no-op if column exists in SQLite 3.37+,
        # but older versions raise; we catch and ignore)
        for migration in [
            "ALTER TABLE rules ADD COLUMN include_genres TEXT",
            "ALTER TABLE media_items ADD COLUMN plex_rating_key INTEGER",
            "ALTER TABLE media_items ADD COLUMN reminder_sent_days TEXT",
        ]:
            try:
                await db.execute(migration)
            except Exception:
                pass
        await _migrate_discord_agent(db)
        await db.commit()


async def _seed_settings(db):
    for key, value in DEFAULT_SETTINGS.items():
        await db.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, value)
        )


async def _seed_rules(db):
    count = await (await db.execute("SELECT COUNT(*) FROM rules")).fetchone()
    if count[0] == 0:
        for rule in DEFAULT_RULES:
            await db.execute(
                """INSERT INTO rules
                   (name, media_type, enabled, added_months, unwatched_months,
                    max_rating, min_rating, max_plays, min_size_gb, exclude_genres, sort_order)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    rule["name"], rule["media_type"], rule["enabled"],
                    rule["added_months"], rule["unwatched_months"],
                    rule["max_rating"], rule["min_rating"],
                    rule["max_plays"], rule["min_size_gb"],
                    rule["exclude_genres"], rule["sort_order"],
                ),
            )



async def _migrate_discord_agent(db):
    """One-time migration: create a Discord notification agent from legacy discord_webhook_url setting."""
    count = await (await db.execute("SELECT COUNT(*) FROM notification_agents")).fetchone()
    if count[0] > 0:
        return  # Already has agents — skip
    row = await (await db.execute("SELECT value FROM settings WHERE key='discord_webhook_url'")).fetchone()
    if not row or not row[0]:
        return  # No old webhook to migrate
    webhook_url = row[0]
    old = {}
    for key in ("discord_mention", "discord_avatar_url"):
        r = await (await db.execute("SELECT value FROM settings WHERE key=?", (key,))).fetchone()
        old[key] = r[0] if r and r[0] else ""
    config = json.dumps({
        "webhook_url": webhook_url,
        "mention": old.get("discord_mention", ""),
        "avatar_url": old.get("discord_avatar_url", ""),
    })
    events = json.dumps(["condemned", "reminder", "deleted", "clean_scan"])
    await db.execute(
        "INSERT INTO notification_agents (name, agent_type, enabled, config, events, created_at) VALUES (?,?,?,?,?,?)",
        ("Discord", "discord", 1, config, events, datetime.now(timezone.utc).isoformat()),
    )

    # Also migrate reminder_days from discord_reminder_days if set
    r = await (await db.execute("SELECT value FROM settings WHERE key='discord_reminder_days'")).fetchone()
    if r and r[0]:
        await db.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ("reminder_days", r[0])
        )


# ── Notification agents ────────────────────────────────────────────────────────

async def get_notification_agents(enabled_only: bool = False) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        query = "SELECT * FROM notification_agents"
        if enabled_only:
            query += " WHERE enabled=1"
        query += " ORDER BY id"
        rows = await (await db.execute(query)).fetchall()
        return [dict(r) for r in rows]


async def get_notification_agent(agent_id: int) -> dict | None:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        row = await (await db.execute(
            "SELECT * FROM notification_agents WHERE id=?", (agent_id,)
        )).fetchone()
        return dict(row) if row else None


async def upsert_notification_agent(agent: dict) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        if agent.get("id"):
            await db.execute(
                "UPDATE notification_agents SET name=?, agent_type=?, enabled=?, config=?, events=? WHERE id=?",
                (agent["name"], agent["agent_type"], agent.get("enabled", 1),
                 agent.get("config", "{}"), agent.get("events", "[]"), agent["id"]),
            )
            await db.commit()
            return agent["id"]
        else:
            cursor = await db.execute(
                "INSERT INTO notification_agents (name, agent_type, enabled, config, events, created_at) VALUES (?,?,?,?,?,?)",
                (agent["name"], agent["agent_type"], agent.get("enabled", 1),
                 agent.get("config", "{}"), agent.get("events", "[]"),
                 datetime.now(timezone.utc).isoformat()),
            )
            await db.commit()
            return cursor.lastrowid


async def delete_notification_agent(agent_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM notification_agents WHERE id=?", (agent_id,))
        await db.commit()


async def get_connection_settings() -> dict:
    """Return all connection-related settings as a dict."""
    keys = [
        "radarr_url", "radarr_api_key", "radarr_public_url",
        "sonarr_url", "sonarr_api_key", "sonarr_public_url",
        "plex_url", "plex_token", "plex_public_url",
        "tautulli_url", "tautulli_api_key", "tautulli_public_url",
        "discord_webhook_url",
    ]
    async with aiosqlite.connect(DB_PATH) as db:
        rows = await (await db.execute(
            f"SELECT key, value FROM settings WHERE key IN ({','.join('?' * len(keys))})",
            keys,
        )).fetchall()
        result = {k: "" for k in keys}
        result.update({k: v for k, v in rows})
        return result


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def get_setting(key: str) -> str | None:
    async with aiosqlite.connect(DB_PATH) as db:
        row = await (await db.execute("SELECT value FROM settings WHERE key=?", (key,))).fetchone()
        return row[0] if row else None


async def get_all_settings() -> dict:
    async with aiosqlite.connect(DB_PATH) as db:
        rows = await (await db.execute("SELECT key, value FROM settings")).fetchall()
        return {k: v for k, v in rows}


async def set_setting(key: str, value: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value)
        )
        await db.commit()


async def set_settings_bulk(pairs: dict[str, str]):
    """Write multiple settings in a single DB connection and transaction."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executemany(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            list(pairs.items()),
        )
        await db.commit()


async def get_rules(enabled_only: bool = False) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        query = "SELECT * FROM rules"
        if enabled_only:
            query += " WHERE enabled=1"
        query += " ORDER BY sort_order, id"
        rows = await (await db.execute(query)).fetchall()
        return [dict(r) for r in rows]


async def get_rule(rule_id: int) -> dict | None:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        row = await (await db.execute("SELECT * FROM rules WHERE id=?", (rule_id,))).fetchone()
        return dict(row) if row else None


async def upsert_rule(rule: dict) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        if rule.get("id"):
            await db.execute(
                """UPDATE rules SET name=?, media_type=?, enabled=?, added_months=?,
                   unwatched_months=?, max_rating=?, min_rating=?, max_plays=?,
                   min_size_gb=?, exclude_genres=?, include_genres=?, sort_order=? WHERE id=?""",
                (rule["name"], rule["media_type"], rule.get("enabled", 1),
                 rule.get("added_months"), rule.get("unwatched_months"),
                 rule.get("max_rating"), rule.get("min_rating"),
                 rule.get("max_plays"), rule.get("min_size_gb"),
                 rule.get("exclude_genres"), rule.get("include_genres"),
                 rule.get("sort_order", 0), rule["id"]),
            )
            await db.commit()
            return rule["id"]
        else:
            cursor = await db.execute(
                """INSERT INTO rules
                   (name, media_type, enabled, added_months, unwatched_months,
                    max_rating, min_rating, max_plays, min_size_gb, exclude_genres, include_genres, sort_order)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (rule["name"], rule.get("media_type", "both"), rule.get("enabled", 1),
                 rule.get("added_months"), rule.get("unwatched_months"),
                 rule.get("max_rating"), rule.get("min_rating"),
                 rule.get("max_plays"), rule.get("min_size_gb"),
                 rule.get("exclude_genres"), rule.get("include_genres"),
                 rule.get("sort_order", 0)),
            )
            await db.commit()
            return cursor.lastrowid


async def delete_rule(rule_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM rules WHERE id=?", (rule_id,))
        await db.commit()


async def upsert_media_item(item: dict):
    async with aiosqlite.connect(DB_PATH) as db:
        item["updated_at"] = now_iso()
        if isinstance(item.get("genres"), list):
            item["genres"] = json.dumps(item["genres"])
        if isinstance(item.get("criteria_matched"), list):
            item["criteria_matched"] = json.dumps(item["criteria_matched"])
        await db.execute(
            """INSERT INTO media_items
               (id, media_type, arr_id, title, year, imdb_rating, genres, added_date,
                last_watched_date, max_watch_percent, total_plays, size_bytes,
                criteria_matched, status, death_row_date, condemned_date, pardon_reason, updated_at)
               VALUES (:id, :media_type, :arr_id, :title, :year, :imdb_rating, :genres, :added_date,
                       :last_watched_date, :max_watch_percent, :total_plays, :size_bytes,
                       :criteria_matched, :status, :death_row_date, :condemned_date, :pardon_reason, :updated_at)
               ON CONFLICT(id) DO UPDATE SET
                 title=excluded.title, year=excluded.year, imdb_rating=excluded.imdb_rating,
                 genres=excluded.genres, added_date=excluded.added_date,
                 last_watched_date=excluded.last_watched_date,
                 max_watch_percent=excluded.max_watch_percent, total_plays=excluded.total_plays,
                 size_bytes=excluded.size_bytes, criteria_matched=excluded.criteria_matched,
                 status=excluded.status, death_row_date=excluded.death_row_date,
                 condemned_date=excluded.condemned_date, updated_at=excluded.updated_at""",
            item,
        )
        await db.commit()


async def get_media_item(item_id: str) -> dict | None:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        row = await (await db.execute("SELECT * FROM media_items WHERE id=?", (item_id,))).fetchone()
        if not row:
            return None
        d = dict(row)
        d["genres"] = json.loads(d["genres"]) if d.get("genres") else []
        d["criteria_matched"] = json.loads(d["criteria_matched"]) if d.get("criteria_matched") else []
        return d


async def get_media_items(status: str | None = None, media_type: str | None = None) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        conditions, params = [], []
        if status:
            conditions.append("status=?")
            params.append(status)
        if media_type:
            conditions.append("media_type=?")
            params.append(media_type)
        query = "SELECT * FROM media_items"
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY title"
        rows = await (await db.execute(query, params)).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["genres"] = json.loads(d["genres"]) if d.get("genres") else []
            d["criteria_matched"] = json.loads(d["criteria_matched"]) if d.get("criteria_matched") else []
            result.append(d)
        return result


async def get_all_media_items_map() -> dict:
    """Load all existing media_items keyed by id. Used by scanner to avoid per-item reads."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        rows = await (await db.execute("SELECT * FROM media_items")).fetchall()
        result = {}
        for row in rows:
            d = dict(row)
            d["criteria_matched"] = json.loads(d["criteria_matched"]) if d.get("criteria_matched") else []
            result[d["id"]] = d
        return result


async def batch_upsert_media_items(items: list[dict]):
    """Write all media item updates in a single executemany call (one round-trip)."""
    if not items:
        return
    ts = now_iso()
    sql = """INSERT INTO media_items
               (id, media_type, arr_id, title, year, imdb_rating, genres, added_date,
                last_watched_date, max_watch_percent, total_plays, size_bytes,
                criteria_matched, status, death_row_date, condemned_date, pardon_reason,
                plex_rating_key, reminder_sent_days, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                 title=excluded.title, year=excluded.year, imdb_rating=excluded.imdb_rating,
                 genres=excluded.genres, added_date=excluded.added_date,
                 last_watched_date=excluded.last_watched_date,
                 max_watch_percent=excluded.max_watch_percent, total_plays=excluded.total_plays,
                 size_bytes=excluded.size_bytes, criteria_matched=excluded.criteria_matched,
                 status=excluded.status, death_row_date=excluded.death_row_date,
                 condemned_date=excluded.condemned_date,
                 plex_rating_key=excluded.plex_rating_key,
                 reminder_sent_days=excluded.reminder_sent_days, updated_at=excluded.updated_at"""

    rows = []
    for item in items:
        genres = item.get("genres")
        criteria = item.get("criteria_matched")
        rows.append((
            item["id"], item["media_type"], item["arr_id"], item["title"],
            item.get("year"), item.get("imdb_rating"),
            json.dumps(genres) if isinstance(genres, list) else genres,
            item.get("added_date"), item.get("last_watched_date"),
            item.get("max_watch_percent"), item.get("total_plays", 0),
            item.get("size_bytes"),
            json.dumps(criteria) if isinstance(criteria, list) else criteria,
            item.get("status", "ok"), item.get("death_row_date"),
            item.get("condemned_date"), item.get("pardon_reason"),
            item.get("plex_rating_key"), item.get("reminder_sent_days"), ts,
        ))

    async with aiosqlite.connect(DB_PATH) as db:
        await db.executemany(sql, rows)
        await db.commit()


async def pardon_item(item_id: str, reason: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE media_items SET status='pardoned', pardon_reason=?, updated_at=? WHERE id=?",
            (reason, now_iso(), item_id),
        )
        await db.commit()


async def unpardon_item(item_id: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE media_items SET status='ok', pardon_reason=NULL, death_row_date=NULL, updated_at=? WHERE id=?",
            (now_iso(), item_id),
        )
        await db.commit()


async def expedite_item(item_id: str, new_death_row_date: str) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE media_items SET death_row_date=?, updated_at=? WHERE id=?",
            (new_death_row_date, now_iso(), item_id),
        )
        await db.commit()


async def start_scan_run(dry_run: bool) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "INSERT INTO scan_runs (started_at, dry_run) VALUES (?, ?)",
            (now_iso(), 1 if dry_run else 0),
        )
        await db.commit()
        return cursor.lastrowid


async def finish_scan_run(run_id: int, stats: dict):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """UPDATE scan_runs SET completed_at=?, new_candidates=?, condemned_count=?,
               deleted_count=?, space_freed_bytes=? WHERE id=?""",
            (now_iso(), stats.get("condemned_count", 0), stats.get("condemned_count", 0),
             stats.get("deleted_count", 0), stats.get("space_freed_bytes", 0), run_id),
        )
        await db.commit()


async def get_library_page(
    q: str = "",
    media_type: str = "",
    status: str = "",
    watched: str = "",
    sort: str = "title",
    order: str = "asc",
    page: int = 1,
    per_page: int = 100,
) -> tuple[list[dict], int]:
    """Return a filtered, sorted, paginated list of media items and the total count."""
    allowed_sorts = {
        "title", "year", "imdb_rating", "added_date",
        "last_watched_date", "total_plays", "size_bytes", "status",
    }
    if sort not in allowed_sorts:
        sort = "title"
    order_sql = "ASC" if order != "desc" else "DESC"

    conditions, params = [], []
    if q:
        conditions.append("LOWER(title) LIKE ?")
        params.append(f"%{q.lower()}%")
    if media_type:
        conditions.append("media_type = ?")
        params.append(media_type)
    if status:
        conditions.append("status = ?")
        params.append(status)
    else:
        # Hide deleted items unless explicitly requested
        conditions.append("status != 'deleted'")
    if watched == "yes":
        conditions.append("total_plays > 0")
    elif watched == "no":
        conditions.append("(total_plays = 0 OR total_plays IS NULL)")

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    offset = (page - 1) * per_page

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        total_row = await (await db.execute(
            f"SELECT COUNT(*) FROM media_items {where}", params
        )).fetchone()
        total = total_row[0] if total_row else 0

        # Treat null as the largest value: last in ASC, first in DESC.
        # ({sort} IS NULL) is 0 for real values, 1 for null. Sorting it with
        # the same direction as the main column achieves largest-null semantics.
        rows = await (await db.execute(
            f"SELECT * FROM media_items {where} ORDER BY ({sort} IS NULL) {order_sql}, {sort} {order_sql} LIMIT ? OFFSET ?",
            params + [per_page, offset],
        )).fetchall()

    result = []
    for row in rows:
        d = dict(row)
        d["genres"] = json.loads(d["genres"]) if d.get("genres") else []
        d["criteria_matched"] = json.loads(d["criteria_matched"]) if d.get("criteria_matched") else []
        result.append(d)
    return result, total


async def get_recent_scan_runs(limit: int = 5) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        rows = await (await db.execute(
            "SELECT * FROM scan_runs ORDER BY id DESC LIMIT ?", (limit,)
        )).fetchall()
        return [dict(r) for r in rows]


async def get_report_library_stats() -> dict:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        row = await (await db.execute("""
            SELECT
              COUNT(*)                                                                 AS total_items,
              SUM(CASE WHEN media_type='movie' THEN 1 ELSE 0 END)                     AS movie_count,
              SUM(CASE WHEN media_type='show'  THEN 1 ELSE 0 END)                     AS show_count,
              COALESCE(SUM(size_bytes), 0)                                             AS total_bytes,
              SUM(CASE WHEN (total_plays IS NULL OR total_plays=0) THEN 1 ELSE 0 END) AS never_watched,
              SUM(CASE WHEN status='condemned' THEN 1 ELSE 0 END)                     AS condemned_count,
              COALESCE(SUM(CASE WHEN status='condemned' THEN size_bytes ELSE 0 END), 0) AS condemned_bytes,
              SUM(CASE WHEN status='pardoned' THEN 1 ELSE 0 END)                      AS pardoned_count
            FROM media_items WHERE status != 'deleted'
        """)).fetchone()
        return dict(row) if row else {}


async def get_report_deletion_totals() -> dict:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        row = await (await db.execute("""
            SELECT
              COALESCE(SUM(deleted_count), 0)     AS total_deleted,
              COALESCE(SUM(space_freed_bytes), 0) AS total_freed_bytes
            FROM scan_runs
        """)).fetchone()
        return dict(row) if row else {}


async def get_report_scan_history(limit: int = 10) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        rows = await (await db.execute(
            "SELECT id, started_at, deleted_count, space_freed_bytes "
            "FROM scan_runs WHERE dry_run = 0 ORDER BY id DESC LIMIT ?", (limit,)
        )).fetchall()
        return [dict(r) for r in rows]


async def get_report_age_buckets() -> dict:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        row = await (await db.execute("""
            SELECT
              SUM(CASE WHEN julianday('now') - julianday(added_date) < 365           THEN 1 ELSE 0 END) AS under_1yr,
              SUM(CASE WHEN julianday('now') - julianday(added_date) BETWEEN 365 AND 729  THEN 1 ELSE 0 END) AS yr_1_2,
              SUM(CASE WHEN julianday('now') - julianday(added_date) BETWEEN 730 AND 1094 THEN 1 ELSE 0 END) AS yr_2_3,
              SUM(CASE WHEN julianday('now') - julianday(added_date) BETWEEN 1095 AND 1824 THEN 1 ELSE 0 END) AS yr_3_5,
              SUM(CASE WHEN julianday('now') - julianday(added_date) >= 1825         THEN 1 ELSE 0 END) AS over_5yr
            FROM media_items WHERE status != 'deleted' AND added_date IS NOT NULL
        """)).fetchone()
        return dict(row) if row else {}


async def get_report_watch_stats() -> dict:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        row = await (await db.execute("""
            SELECT
              SUM(CASE WHEN total_plays > 0 THEN 1 ELSE 0 END)                            AS watched_count,
              SUM(CASE WHEN total_plays = 0 OR total_plays IS NULL THEN 1 ELSE 0 END)      AS unwatched_count,
              ROUND(AVG(CASE WHEN total_plays > 0 THEN max_watch_percent END), 1)          AS avg_watch_pct,
              SUM(CASE WHEN last_watched_date >= date('now', '-90 days') THEN 1 ELSE 0 END) AS watched_last_90d
            FROM media_items WHERE status != 'deleted'
        """)).fetchone()
        return dict(row) if row else {}


async def get_report_top_condemned(limit: int = 5) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        rows = await (await db.execute(
            "SELECT id, title, media_type, size_bytes, criteria_matched, imdb_rating "
            "FROM media_items WHERE status = 'condemned' "
            "ORDER BY size_bytes DESC LIMIT ?", (limit,)
        )).fetchall()
        return [dict(r) for r in rows]


async def get_report_timeline_data() -> dict:
    """Returns condemned/deleted/pardoned counts bucketed by week, month, and year."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        async def _fetch(sql: str) -> dict:
            rows = await (await db.execute(sql)).fetchall()
            return {r["period"]: r["count"] for r in rows}

        # Yearly (all time)
        y_del = await _fetch("SELECT strftime('%Y', updated_at) AS period, COUNT(*) AS count FROM media_items WHERE status='deleted' AND updated_at IS NOT NULL GROUP BY period ORDER BY period")
        y_con = await _fetch("SELECT strftime('%Y', death_row_date) AS period, COUNT(*) AS count FROM media_items WHERE death_row_date IS NOT NULL AND death_row_date != '' GROUP BY period ORDER BY period")
        y_par = await _fetch("SELECT strftime('%Y', updated_at) AS period, COUNT(*) AS count FROM media_items WHERE status='pardoned' AND updated_at IS NOT NULL GROUP BY period ORDER BY period")

        # Monthly (last 24 months)
        m_del = await _fetch("SELECT strftime('%Y-%m', updated_at) AS period, COUNT(*) AS count FROM media_items WHERE status='deleted' AND updated_at >= date('now','-24 months') GROUP BY period ORDER BY period")
        m_con = await _fetch("SELECT strftime('%Y-%m', death_row_date) AS period, COUNT(*) AS count FROM media_items WHERE death_row_date IS NOT NULL AND death_row_date != '' AND death_row_date >= date('now','-24 months') GROUP BY period ORDER BY period")
        m_par = await _fetch("SELECT strftime('%Y-%m', updated_at) AS period, COUNT(*) AS count FROM media_items WHERE status='pardoned' AND updated_at >= date('now','-24 months') GROUP BY period ORDER BY period")

        # Weekly (last 16 weeks = 112 days; SQLite has no 'weeks' modifier)
        w_del = await _fetch("SELECT strftime('%Y-W%W', updated_at) AS period, COUNT(*) AS count FROM media_items WHERE status='deleted' AND updated_at >= date('now','-112 days') GROUP BY period ORDER BY period")
        w_con = await _fetch("SELECT strftime('%Y-W%W', death_row_date) AS period, COUNT(*) AS count FROM media_items WHERE death_row_date IS NOT NULL AND death_row_date != '' AND death_row_date >= date('now','-112 days') GROUP BY period ORDER BY period")
        w_par = await _fetch("SELECT strftime('%Y-W%W', updated_at) AS period, COUNT(*) AS count FROM media_items WHERE status='pardoned' AND updated_at >= date('now','-112 days') GROUP BY period ORDER BY period")

        return {
            "yearly":  {"condemned": y_con, "deleted": y_del, "pardoned": y_par},
            "monthly": {"condemned": m_con, "deleted": m_del, "pardoned": m_par},
            "weekly":  {"condemned": w_con, "deleted": w_del, "pardoned": w_par},
        }


async def log_audit(action: str, detail: str = "", ip: str = "") -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO audit_log (timestamp, action, detail, ip) VALUES (?,?,?,?)",
            (now_iso(), action, detail, ip),
        )
        await db.commit()


async def get_auth_username() -> str:
    return (await get_setting("auth_username")) or "Admin"


async def set_auth_username(username: str) -> None:
    await set_setting("auth_username", username)


async def get_auth_password_hash() -> str | None:
    """Return the stored PBKDF2 password hash, or None if not yet configured."""
    return await get_setting("auth_password_hash")


async def set_auth_password_hash(h: str) -> None:
    """Persist the PBKDF2 password hash."""
    await set_setting("auth_password_hash", h)


async def is_totp_enabled() -> bool:
    return (await get_setting("totp_enabled")) == "true"


async def get_totp_secret() -> str | None:
    return await get_setting("totp_secret")


async def enable_totp(secret: str, backup_hashes: list[str]) -> None:
    import json
    await set_setting("totp_secret", secret)
    await set_setting("totp_backup_hashes", json.dumps(backup_hashes))
    await set_setting("totp_enabled", "true")


async def disable_totp() -> None:
    await set_setting("totp_enabled", "false")
    await set_setting("totp_secret", "")
    await set_setting("totp_backup_hashes", "[]")


async def get_totp_backup_hashes() -> list[str]:
    import json
    raw = await get_setting("totp_backup_hashes")
    try:
        return json.loads(raw) if raw else []
    except Exception:
        return []


async def set_totp_backup_hashes(hashes: list[str]) -> None:
    import json
    await set_setting("totp_backup_hashes", json.dumps(hashes))


async def get_passkeys() -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        rows = await (await db.execute("SELECT * FROM passkeys ORDER BY created_at")).fetchall()
        return [dict(r) for r in rows]


async def add_passkey(credential_id: bytes, public_key: bytes, sign_count: int, name: str) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "INSERT INTO passkeys (credential_id, public_key, sign_count, name, created_at) VALUES (?,?,?,?,?)",
            (credential_id, public_key, sign_count, name, now_iso()),
        )
        await db.commit()
        return cursor.lastrowid


async def get_passkey_by_credential_id(credential_id: bytes) -> dict | None:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        row = await (await db.execute(
            "SELECT * FROM passkeys WHERE credential_id=?", (credential_id,)
        )).fetchone()
        return dict(row) if row else None


async def update_passkey_sign_count(credential_id: bytes, sign_count: int) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE passkeys SET sign_count=? WHERE credential_id=?", (sign_count, credential_id)
        )
        await db.commit()


async def delete_passkey(passkey_id: int) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM passkeys WHERE id=?", (passkey_id,))
        await db.commit()


async def get_audit_log(limit: int = 200, offset: int = 0) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        rows = await (await db.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset)
        )).fetchall()
        return [dict(r) for r in rows]


async def get_stats() -> dict:
    async with aiosqlite.connect(DB_PATH) as db:
        condemned = await (await db.execute(
            "SELECT COUNT(*), COALESCE(SUM(size_bytes),0) FROM media_items WHERE status='condemned'"
        )).fetchone()
        last_run = await (await db.execute(
            "SELECT started_at, completed_at FROM scan_runs ORDER BY id DESC LIMIT 1"
        )).fetchone()
        return {
            "condemned_count": condemned[0],
            "condemned_bytes": condemned[1],
            "last_run_at": last_run[0] if last_run else None,
            "last_run_completed": last_run[1] if last_run else None,
        }


# ── Backup / Restore ──────────────────────────────────────────────────────────

_AUTH_KEYS = frozenset({
    "auth_password_hash", "auth_username",
    "totp_enabled", "totp_secret", "totp_backup_hashes",
})


async def export_config() -> dict:
    """Export settings, rules, and notification agents as a portable dict."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        settings_rows = await (await db.execute("SELECT key, value FROM settings")).fetchall()
        settings = {r["key"]: r["value"] for r in settings_rows}
        rules_rows = await (await db.execute("SELECT * FROM rules ORDER BY sort_order")).fetchall()
        rules = [dict(r) for r in rules_rows]
        agents_rows = await (await db.execute("SELECT * FROM notification_agents ORDER BY id")).fetchall()
        agents = [dict(r) for r in agents_rows]
    return {
        "version": 1,
        "type": "warden_config",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "settings": settings,
        "rules": rules,
        "notification_agents": agents,
    }


async def import_config(data: dict) -> None:
    """Restore settings, rules, and notification agents from a config backup dict."""
    async with aiosqlite.connect(DB_PATH) as db:
        # Settings — skip auth keys to prevent accidental lockout
        for key, value in data.get("settings", {}).items():
            if key not in _AUTH_KEYS:
                await db.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value)
                )
        # Rules — full replace
        await db.execute("DELETE FROM rules")
        for rule in data.get("rules", []):
            rule = {k: v for k, v in rule.items() if k != "id"}
            cols = ", ".join(rule.keys())
            placeholders = ", ".join("?" * len(rule))
            await db.execute(
                f"INSERT INTO rules ({cols}) VALUES ({placeholders})", list(rule.values())
            )
        # Notification agents — full replace
        await db.execute("DELETE FROM notification_agents")
        for agent in data.get("notification_agents", []):
            agent = {k: v for k, v in agent.items() if k != "id"}
            cols = ", ".join(agent.keys())
            placeholders = ", ".join("?" * len(agent))
            await db.execute(
                f"INSERT INTO notification_agents ({cols}) VALUES ({placeholders})", list(agent.values())
            )
        await db.commit()


def _full_backup_sync() -> bytes:
    """Return the entire SQLite database as bytes using the backup API (runs in thread)."""
    import sqlite3, tempfile, os
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    try:
        src = sqlite3.connect(DB_PATH)
        dst = sqlite3.connect(tmp.name)
        src.backup(dst)
        src.close()
        dst.close()
        return Path(tmp.name).read_bytes()
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass
