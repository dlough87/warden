"""
Main scan orchestrator.

Flow:
1. Fetch all movies (Radarr) + shows (Sonarr)
2. Build Tautulli watch map (primary) + Plex fallback map
3. Load all existing DB records into memory (single read)
4. Enrich each item with watch data + evaluate against enabled rules
5. Determine status transitions (all in memory)
6. Batch write all changes in one transaction
7. Send Discord notifications for newly condemned items
8. In live mode: delete condemned items
"""

import asyncio
import json
import logging
from datetime import date, timedelta

from .config import get_config_async
from .database import (
    DB_PATH, get_setting, set_setting, get_rules, get_all_media_items_map,
    batch_upsert_media_items, start_scan_run, finish_scan_run, now_iso,
)
from .criteria import evaluate
from .sources.radarr import RadarrClient
from .sources.sonarr import SonarrClient
from .sources.tautulli import TautulliClient
from .sources.plex import PlexClient
from . import notifications

log = logging.getLogger(__name__)

_scan_running = False


def is_running() -> bool:
    return _scan_running


async def run_scan():
    global _scan_running
    if _scan_running:
        log.warning("Scan already in progress — skipping")
        return

    _scan_running = True
    try:
        await _do_scan()
    finally:
        _scan_running = False


async def _do_scan():
    cfg = await get_config_async()
    dry_run = (await get_setting("dry_run") or "true").lower() == "true"
    threshold = float(await get_setting("watch_threshold_percent") or 80)
    death_row_days = int(await get_setting("death_row_days") or 30)

    run_id = await start_scan_run(dry_run)
    log.info(f"=== Warden scan starting (dry_run={dry_run}) ===")

    stats = {"condemned_count": 0, "deleted_count": 0, "space_freed_bytes": 0}

    # --- Fetch media ---
    radarr = RadarrClient(cfg.radarr.url, cfg.radarr.api_key)
    sonarr = SonarrClient(cfg.sonarr.url, cfg.sonarr.api_key)
    movies = await radarr.get_movies()
    shows = await sonarr.get_series()
    all_media = movies + shows

    # --- Build watch maps ---
    tautulli = TautulliClient(cfg.tautulli.url, cfg.tautulli.api_key)
    plex = PlexClient(cfg.plex.url, cfg.plex.token)

    tautulli_map = await tautulli.get_watch_map(threshold)
    plex_fallback, plex_added_at, plex_rating_keys = await plex.build_plex_maps()

    # Cache machine identifier for Plex deep links (fetch once per scan)
    machine_id = await plex.get_machine_identifier()
    if machine_id:
        await set_setting("plex_machine_id", machine_id)

    # --- Load all existing DB records in one shot (avoids per-item reads) ---
    existing_map = await get_all_media_items_map()

    # --- Load rules ---
    rules = await get_rules(enabled_only=True)
    log.info(f"Evaluating {len(all_media)} items against {len(rules)} rules")

    today = date.today()
    newly_condemned = []
    items_to_write = []

    for i, media in enumerate(all_media):
        # Yield to the event loop every 50 items so the UI stays responsive
        if i % 50 == 0:
            await asyncio.sleep(0)
        title = media["title"]
        year = media.get("year")

        plex_key = (title.strip().lower(), year)
        plex_key_noyear = (title.strip().lower(), None)

        # --- Watch data ---
        # Tautulli: threshold-filtered sessions, limited to Tautulli install date
        # Plex: all-time history, no threshold precision (fires at ~90%)
        tautulli_watch = tautulli.lookup(tautulli_map, title, year)
        plex_watch = plex_fallback.get(plex_key)
        if plex_watch is None and year is not None:
            plex_watch = plex_fallback.get(plex_key_noyear)

        # last_watched: Tautulli is authoritative — threshold-filtered, precise.
        # Plex lastViewedAt is only used when Tautulli has no sessions at all for
        # this item (i.e. pre-dates Tautulli install). Never mix sources here —
        # Plex fires at ~90% but has no per-session threshold control, so using
        # it alongside Tautulli data would corrupt the threshold-based logic.
        tautulli_last = tautulli_watch["last_watched"] if tautulli_watch else None
        plex_last = plex_watch["last_watched"] if plex_watch else None
        last_watched = tautulli_last if tautulli_watch else plex_last

        # max_watch_percent + total_plays: Tautulli primary (precise), Plex fallback
        # Do NOT combine play counts — would double-count overlapping history
        if tautulli_watch:
            max_watch_percent = tautulli_watch["max_percent"]
            total_plays = tautulli_watch["total_plays"]
        elif plex_watch:
            max_watch_percent = plex_watch["max_percent"]  # fixed 90.0
            total_plays = plex_watch["total_plays"]
        else:
            max_watch_percent = None
            total_plays = 0

        # --- Added date ---
        # Resets and migrations always push dates forward (make items appear newer).
        # Taking the minimum across sources therefore gives the most accurate date.
        # Movies: min(Radarr movieFile.dateAdded, Plex addedAt, Plex lastViewedAt)
        # Shows:  min(Sonarr series.added, Plex addedAt, Plex lastViewedAt)
        # Plex lastViewedAt predates both Radarr/Sonarr migrations and Plex library
        # rebuilds — if a movie was watched 11yr ago it was in the collection then.
        arr_added = media.get("added_date")
        plex_added = plex_added_at.get(plex_key)
        if plex_added is None and year is not None:
            plex_added = plex_added_at.get(plex_key_noyear)
        added_candidates = [d for d in [arr_added, plex_added, plex_last] if d]
        added_date = min(added_candidates) if added_candidates else None

        plex_rating_key = plex_rating_keys.get(plex_key)
        if plex_rating_key is None and year is not None:
            plex_rating_key = plex_rating_keys.get(plex_key_noyear)

        item = {
            **media,
            "added_date": added_date,
            "last_watched_date": last_watched,
            "max_watch_percent": max_watch_percent,
            "total_plays": total_plays,
            "plex_rating_key": plex_rating_key,
        }

        matched_rules = evaluate(item, rules)

        # Get existing record from in-memory map
        existing = existing_map.get(item["id"])
        current_status = existing["status"] if existing else "ok"
        current_death_row_date = existing["death_row_date"] if existing else None

        existing_reminder_sent = existing.get("reminder_sent_days") if existing else None

        # Pardoned items are never re-evaluated
        if current_status == "pardoned":
            items_to_write.append({
                **item,
                "criteria_matched": matched_rules,
                "status": "pardoned",
                "death_row_date": current_death_row_date,
                "condemned_date": existing.get("condemned_date") if existing else None,
                "pardon_reason": existing.get("pardon_reason") if existing else None,
                "reminder_sent_days": existing_reminder_sent,
            })
            continue

        if matched_rules:
            if current_status not in ("condemned", "pardoned"):
                # Newly condemned — straight to death row, no candidate staging
                new_status = "condemned"
                death_row_date = today.isoformat()
                condemned_date = today.isoformat()
                newly_condemned.append({**item, "criteria_matched": matched_rules})
                stats["condemned_count"] += 1
                log.info(f"  CONDEMNED: {title} ({year}) — {matched_rules}")
            else:
                # Already on death row — preserve the original date
                death_row_date = current_death_row_date or today.isoformat()
                condemned_date = (existing.get("condemned_date") if existing else None) or today.isoformat()
                new_status = "condemned"

            items_to_write.append({
                **item,
                "criteria_matched": matched_rules,
                "status": new_status,
                "death_row_date": death_row_date,
                "condemned_date": condemned_date,
                "pardon_reason": None,
                "reminder_sent_days": existing_reminder_sent,
            })
        else:
            if current_status == "condemned":
                log.info(f"  CLEARED: {title} ({year}) — no longer matches any rule")
            items_to_write.append({
                **item,
                "criteria_matched": [],
                "status": "ok",
                "death_row_date": None,
                "condemned_date": None,
                "pardon_reason": None,
                "reminder_sent_days": None,  # reset so reminders re-fire if re-condemned
            })

    # --- Single batch write (one transaction, UI never blocked) ---
    log.info(f"Evaluation complete. Writing {len(items_to_write)} items to database...")
    await batch_upsert_media_items(items_to_write)
    log.info("Database write complete.")

    # --- Notifications ---
    log.info("Sending notifications...")
    if newly_condemned:
        await notifications.dispatch("condemned", items=newly_condemned, dry_run=dry_run, death_row_days=death_row_days)
    else:
        await notifications.dispatch("clean_scan", dry_run=dry_run)

    # --- Deletions (items that have served their full death row sentence) ---
    due_for_deletion = [
        item for item in items_to_write
        if item.get("status") == "condemned"
        and item.get("death_row_date")
        and (today - date.fromisoformat(item["death_row_date"])).days >= death_row_days
    ]

    # --- Death row reminders ---
    # Collect unique thresholds from all reminder-subscribed agents
    from .database import get_notification_agents as _get_agents
    _all_agents = await _get_agents(enabled_only=True)
    _reminder_thresholds: set[int] = set()
    for _a in _all_agents:
        if "reminder" in json.loads(_a.get("events") or "[]"):
            _cfg = json.loads(_a.get("config") or "{}")
            for _x in (_cfg.get("reminder_days") or "").split(","):
                if _x.strip().isdigit():
                    _reminder_thresholds.add(int(_x.strip()))
    reminder_thresholds = sorted(_reminder_thresholds, reverse=True)
    if reminder_thresholds:
        due_ids = {item["id"] for item in due_for_deletion}
        by_threshold: dict[int, list] = {}
        reminder_updates = []
        for item in items_to_write:
            if item.get("status") != "condemned" or item["id"] in due_ids:
                continue
            if not item.get("death_row_date"):
                continue
            days_on = (today - date.fromisoformat(item["death_row_date"])).days
            days_remaining = death_row_days - days_on
            if days_remaining <= 0:
                continue
            sent = json.loads(item.get("reminder_sent_days") or "[]")
            new_sent = list(sent)
            for threshold in reminder_thresholds:
                if days_remaining <= threshold and threshold not in sent:
                    by_threshold.setdefault(threshold, []).append(item)
                    new_sent.append(threshold)
            if new_sent != sent:
                item["reminder_sent_days"] = json.dumps(new_sent)
                reminder_updates.append((json.dumps(new_sent), item["id"]))
        for threshold, reminder_items in sorted(by_threshold.items()):
            await notifications.dispatch("reminder", items=reminder_items, days_remaining=threshold, dry_run=dry_run)
        if reminder_updates:
            import aiosqlite
            async with aiosqlite.connect(DB_PATH) as db:
                await db.executemany(
                    "UPDATE media_items SET reminder_sent_days=? WHERE id=?", reminder_updates
                )
                await db.commit()

    if due_for_deletion:
        if dry_run:
            await notifications.dispatch(
                "deleted",
                items=due_for_deletion,
                space_freed=sum(i.get("size_bytes") or 0 for i in due_for_deletion),
                dry_run=True,
            )
        else:
            for item in due_for_deletion:
                await _delete_item(item, radarr, sonarr, stats)
            if stats["deleted_count"]:
                await notifications.dispatch(
                    "deleted",
                    items=due_for_deletion,
                    space_freed=stats["space_freed_bytes"],
                    dry_run=False,
                )

    await finish_scan_run(run_id, stats)
    log.info(f"=== Scan complete: {stats} ===")


async def _delete_item(item: dict, radarr: RadarrClient, sonarr: SonarrClient, stats: dict):
    try:
        if item["media_type"] == "movie":
            detail = await radarr.get_movie_detail(item["arr_id"])
            await radarr.delete_movie(item["arr_id"])
            if detail.get("tmdb_id"):
                try:
                    await radarr.add_exclusion(detail["tmdb_id"], item["title"], item.get("year"))
                except Exception as e:
                    log.warning(f"  Exclusion failed for {item['title']}: {e}")
        else:
            detail = await sonarr.get_series_detail(item["arr_id"])
            await sonarr.delete_series(item["arr_id"])
            if detail.get("tvdb_id"):
                try:
                    await sonarr.add_exclusion(detail["tvdb_id"], item["title"])
                except Exception as e:
                    log.warning(f"  Exclusion failed for {item['title']}: {e}")

        stats["deleted_count"] += 1
        stats["space_freed_bytes"] += item.get("size_bytes") or 0
        log.info(f"  DELETED: {item['title']} ({item.get('year')})")

        import aiosqlite
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "UPDATE media_items SET status='deleted', updated_at=? WHERE id=?",
                (now_iso(), item["id"]),
            )
            await db.commit()
    except Exception as e:
        log.error(f"  Failed to delete {item['title']}: {e}")
