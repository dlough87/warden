"""
Agent-based notification dispatch for Warden.

Events:
  condemned     — new items sentenced to death row
  reminder      — N days left on death row
  deleted       — items actually deleted (or would be, in dry run)
  delete_failed — items that were due for deletion but the source API failed
  delete_stuck  — items that have failed deletion 3+ times and need manual attention
  clean_scan    — scan completed, nothing new to report
  scan_error    — unhandled error aborted the scan

Each notification_agents row: {id, name, agent_type, enabled, config (JSON), events (JSON array)}
Agent types: discord | pushover | ntfy | apprise | webhook
"""

import httpx
import json
import logging
from datetime import date

log = logging.getLogger(__name__)

CHUNK_SIZE = 20  # Discord embeds per message (other agents truncate at CHUNK_SIZE * 1 batch)
EVENTS = ["condemned", "reminder", "deleted", "delete_failed", "delete_stuck", "clean_scan", "scan_error"]

# Discord embed colours
_COLOR_RED    = 0xE74C3C
_COLOR_GREEN  = 0x2ECC71
_COLOR_ORANGE = 0xF39C12


# ── Shared text helpers ────────────────────────────────────────────────────────

def _format_size(size_bytes: int | None) -> str:
    if not size_bytes:
        return "?"
    gb = size_bytes / 1_073_741_824
    return f"{gb:.1f} GB"


def _format_age(date_str: str | None, label: str = "added") -> str:
    if not date_str:
        return f"{label}: ?"
    try:
        d = date.fromisoformat(date_str)
        days = (date.today() - d).days
        if days < 30:
            return f"{label}: {days}d ago"
        elif days < 365:
            return f"{label}: {days // 30}mo ago"
        else:
            return f"{label}: {days // 365}yr ago"
    except Exception:
        return f"{label}: ?"


def _item_line(item: dict) -> str:
    """One-line summary for Discord embeds."""
    rating = f"{item['imdb_rating']:.1f}" if item.get("imdb_rating") else "?"
    size = _format_size(item.get("size_bytes"))
    added = _format_age(item.get("added_date"), "added")
    last_w = _format_age(item.get("last_watched_date"), "watched") if item.get("last_watched_date") else "never watched"
    title = item.get("title", "Unknown")
    year = item.get("year", "")
    return f"**{title}** ({year}) — ⭐ {rating} | 💾 {size} | {added} | {last_w}"


def _item_line_plain(item: dict) -> str:
    """One-line summary for plain-text agents."""
    rating = f"⭐{item['imdb_rating']:.1f}" if item.get("imdb_rating") else ""
    size = _format_size(item.get("size_bytes"))
    title = item.get("title", "Unknown")
    year = item.get("year", "")
    parts = [f"• {title} ({year})", rating, f"💾 {size}"]
    return "  ".join(p for p in parts if p)


def _chunks(items: list, size: int) -> list[list]:
    return [items[i:i + size] for i in range(0, len(items), size)]


def _build_text_body(event: str, **kwargs) -> tuple[str, str]:
    """Return (title, body) plain-text pair for any event."""
    dry = kwargs.get("dry_run", False)
    dry_tag = " [DRY RUN]" if dry else ""
    items = kwargs.get("items", [])

    if event == "condemned":
        death_row_days = kwargs.get("death_row_days", 30)
        title = f"🚨 {len(items)} New Item(s) on Death Row{dry_tag}"
        item_lines = "\n".join(_item_line_plain(i) for i in items[:CHUNK_SIZE])
        suffix = f"\n…and {len(items) - CHUNK_SIZE} more" if len(items) > CHUNK_SIZE else ""
        action = "NOT executed" if dry else f"executed in {death_row_days} days"
        body = f"{len(items)} item(s) will be {action} unless pardoned.\n\n{item_lines}{suffix}"

    elif event == "reminder":
        days = kwargs.get("days_remaining", 0)
        label = "tomorrow" if days == 1 else f"in {days} days"
        title = f"⏳ {len(items)} Item(s) Condemned {label.title()}{dry_tag}"
        item_lines = "\n".join(_item_line_plain(i) for i in items[:CHUNK_SIZE])
        suffix = f"\n…and {len(items) - CHUNK_SIZE} more" if len(items) > CHUNK_SIZE else ""
        body = f"{len(items)} item(s) will be {'executed ' if not dry else 'executed (dry run — no files touched) '}{label}.\n\n{item_lines}{suffix}"

    elif event == "deleted":
        space_freed = kwargs.get("space_freed", 0)
        verb = "Would Execute" if dry else "Executed"
        title = f"🗑️ Warden {verb} {len(items)} Item(s){dry_tag}"
        item_lines = "\n".join(_item_line_plain(i) for i in items[:CHUNK_SIZE])
        suffix = f"\n…and {len(items) - CHUNK_SIZE} more" if len(items) > CHUNK_SIZE else ""
        body = f"{'Would free' if dry else 'Freed'} {_format_size(space_freed)} of disk space.\n\n{item_lines}{suffix}"

    elif event == "delete_failed":
        title = f"⚠️ Warden: {len(items)} Deletion(s) Failed"
        item_lines = "\n".join(_item_line_plain(i) for i in items[:CHUNK_SIZE])
        suffix = f"\n…and {len(items) - CHUNK_SIZE} more" if len(items) > CHUNK_SIZE else ""
        body = f"{len(items)} item(s) were due for deletion but the source API rejected the request. Warden will retry on the next scan.\n\n{item_lines}{suffix}"

    elif event == "delete_stuck":
        title = f"🛑 Warden: {len(items)} Item(s) Stuck on Death Row"
        item_lines = "\n".join(_item_line_plain(i) for i in items[:CHUNK_SIZE])
        suffix = f"\n…and {len(items) - CHUNK_SIZE} more" if len(items) > CHUNK_SIZE else ""
        body = f"{len(items)} item(s) have failed deletion 3+ times — manual intervention likely needed.\n\n{item_lines}{suffix}"

    elif event == "scan_error":
        title = "⚠️ Warden Scan Failed"
        body = f"An error occurred during the scheduled scan:\n\n{kwargs.get('error', 'Unknown error')}"

    else:  # clean_scan
        title = f"✅ Warden Scan Complete{dry_tag}"
        body = "No new items added to death row this run."

    return title, body


# ── Discord ────────────────────────────────────────────────────────────────────

async def _send_discord(agent: dict, event: str, **kwargs):
    config = json.loads(agent.get("config") or "{}")
    webhook_url = config.get("webhook_url", "").strip()
    if not webhook_url:
        log.warning(f"Discord agent '{agent['name']}' has no webhook URL — skipping")
        return
    mention = config.get("mention", "").strip()
    avatar_url = config.get("avatar_url", "").strip()
    mention_prefix = f"{mention}\n" if mention else ""
    dry = kwargs.get("dry_run", False)
    dry_tag = " [DRY RUN]" if dry else ""

    payload_base: dict = {}
    if avatar_url:
        payload_base["avatar_url"] = avatar_url

    async def post(payload: dict):
        payload.setdefault("username", "Warden")
        payload.update(payload_base)
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(webhook_url, json=payload)
            r.raise_for_status()

    items = kwargs.get("items", [])

    if event == "condemned":
        death_row_days = kwargs.get("death_row_days", 30)
        by_rule: dict[str, list] = {}
        for item in items:
            rule = (item.get("criteria_matched") or ["Unknown"])[0]
            by_rule.setdefault(rule, []).append(item)
        for rule_name, rule_items in by_rule.items():
            for i, chunk in enumerate(_chunks(rule_items, CHUNK_SIZE)):
                lines = "\n".join(_item_line(it) for it in chunk)
                part = f" (part {i+1})" if len(rule_items) > CHUNK_SIZE else ""
                await post({
                    "content": mention_prefix or None,
                    "embeds": [{
                        "title": f"🚨 New Items on Death Row{dry_tag}{part}",
                        "description": (
                            f"**Rule: {rule_name}** — {len(rule_items)} item(s)\n"
                            f"Will be {'**NOT** ' if dry else ''}executed in {death_row_days} days unless pardoned.\n\n{lines}"
                        ),
                        "color": _COLOR_RED,
                        "footer": {"text": "Warden • Pardon items via the UI to save them"},
                    }],
                })

    elif event == "reminder":
        days = kwargs.get("days_remaining", 0)
        if days == 1:
            title = f"⚠️ Condemned Tomorrow{dry_tag}"
            body_days = "**1 day**"
        else:
            title = f"⏳ {days} Days Left on Death Row{dry_tag}"
            body_days = f"**{days} days**"
        by_rule: dict[str, list] = {}
        for item in items:
            rule = (item.get("criteria_matched") or ["Unknown"])[0]
            by_rule.setdefault(rule, []).append(item)
        for rule_name, rule_items in by_rule.items():
            for i, chunk in enumerate(_chunks(rule_items, CHUNK_SIZE)):
                lines = "\n".join(_item_line(it) for it in chunk)
                part = f" (part {i+1})" if len(rule_items) > CHUNK_SIZE else ""
                await post({
                    "content": mention_prefix or None,
                    "embeds": [{
                        "title": f"{title}{part}",
                        "description": (
                            f"**Rule: {rule_name}** — {len(rule_items)} item(s)\n"
                            f"{'Would be executed' if dry else 'Will be executed'} in {body_days}.\n\n{lines}"
                        ),
                        "color": _COLOR_ORANGE,
                        "footer": {"text": "Warden • Pardon items via the UI to save them"},
                    }],
                })

    elif event == "deleted":
        space_freed = kwargs.get("space_freed", 0)
        verb = "Would Execute" if dry else "Executed"
        for i, chunk in enumerate(_chunks(items, CHUNK_SIZE)):
            lines = "\n".join(_item_line(it) for it in chunk)
            part = f" (part {i+1})" if len(items) > CHUNK_SIZE else ""
            await post({
                "content": mention_prefix or None,
                "embeds": [{
                    "title": f"🗑️ Warden {verb} {len(items)} Item(s){dry_tag}{part}",
                    "description": f"{'Would free' if dry else 'Freed'} **{_format_size(space_freed)}** of disk space.\n\n{lines}",
                    "color": _COLOR_ORANGE if dry else _COLOR_RED,
                    "footer": {"text": "Warden • Dry run — no files were touched" if dry else "Warden"},
                }],
            })

    elif event == "delete_failed":
        for i, chunk in enumerate(_chunks(items, CHUNK_SIZE)):
            lines = "\n".join(_item_line(it) for it in chunk)
            part = f" (part {i+1})" if len(items) > CHUNK_SIZE else ""
            await post({
                "content": mention_prefix or None,
                "embeds": [{
                    "title": f"⚠️ Warden: {len(items)} Deletion(s) Failed{part}",
                    "description": (
                        f"These items were due for deletion but the source API rejected the request. "
                        f"Warden will retry on the next scan.\n\n{lines}"
                    ),
                    "color": _COLOR_ORANGE,
                    "footer": {"text": "Warden • Check the server log for the API error"},
                }],
            })

    elif event == "delete_stuck":
        for i, chunk in enumerate(_chunks(items, CHUNK_SIZE)):
            lines = "\n".join(_item_line(it) for it in chunk)
            part = f" (part {i+1})" if len(items) > CHUNK_SIZE else ""
            await post({
                "content": mention_prefix or None,
                "embeds": [{
                    "title": f"🛑 Warden: Items Stuck on Death Row{part}",
                    "description": (
                        f"**{len(items)} item(s)** have now failed deletion 3 or more times. "
                        f"Manual intervention is likely needed — check Radarr/Sonarr logs or pardon the item.\n\n{lines}"
                    ),
                    "color": _COLOR_RED,
                    "footer": {"text": "Warden • Manual attention required"},
                }],
            })

    elif event == "scan_error":
        await post({
            "embeds": [{
                "title": "⚠️ Warden Scan Failed",
                "description": f"An error occurred during the scheduled scan:\n```\n{kwargs.get('error', 'Unknown error')}\n```",
                "color": _COLOR_RED,
                "footer": {"text": "Warden • Check the server log for details"},
            }],
        })

    else:  # clean_scan
        await post({
            "embeds": [{
                "title": f"✅ Warden Scan Complete{dry_tag}",
                "description": "No new items added to death row this run.",
                "color": _COLOR_GREEN,
                "footer": {"text": "Warden"},
            }],
        })


async def _test_discord(config: dict) -> tuple[bool, str]:
    webhook_url = config.get("webhook_url", "").strip()
    if not webhook_url:
        return False, "No webhook URL configured"
    avatar_url = config.get("avatar_url", "").strip()
    payload: dict = {
        "username": "Warden",
        "embeds": [{
            "title": "🛡️ Warden — Test Notification",
            "description": "Connection test successful. Warden can reach this webhook.",
            "color": _COLOR_GREEN,
            "footer": {"text": "Warden"},
        }],
    }
    if avatar_url:
        payload["avatar_url"] = avatar_url
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(webhook_url, json=payload)
        r.raise_for_status()
    return True, "Message sent to Discord"


# ── Pushover ───────────────────────────────────────────────────────────────────

async def _send_pushover(agent: dict, event: str, **kwargs):
    config = json.loads(agent.get("config") or "{}")
    user_key = config.get("user_key", "").strip()
    api_token = config.get("api_token", "").strip()
    if not user_key or not api_token:
        log.warning(f"Pushover agent '{agent['name']}' missing credentials — skipping")
        return
    title, body = _build_text_body(event, **kwargs)
    priority = int(config.get("priority") or 0)
    payload = {
        "token": api_token,
        "user": user_key,
        "title": title,
        "message": body,
        "priority": priority,
    }
    if config.get("device"):
        payload["device"] = config["device"].strip()
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post("https://api.pushover.net/1/messages.json", json=payload)
        r.raise_for_status()


async def _test_pushover(config: dict) -> tuple[bool, str]:
    user_key = config.get("user_key", "").strip()
    api_token = config.get("api_token", "").strip()
    if not user_key or not api_token:
        return False, "Missing user key or API token"
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post("https://api.pushover.net/1/messages.json", json={
            "token": api_token,
            "user": user_key,
            "title": "🛡️ Warden — Test",
            "message": "Connection test successful.",
        })
        r.raise_for_status()
    return True, "Message sent via Pushover"


# ── ntfy ───────────────────────────────────────────────────────────────────────

_NTFY_PRIORITY = {
    "condemned": "high",
    "reminder": "default",
    "deleted": "high",
    "delete_failed": "high",
    "delete_stuck": "urgent",
    "clean_scan": "low",
}

async def _send_ntfy(agent: dict, event: str, **kwargs):
    config = json.loads(agent.get("config") or "{}")
    server_url = config.get("server_url", "https://ntfy.sh").rstrip("/")
    topic = config.get("topic", "").strip()
    if not topic:
        log.warning(f"ntfy agent '{agent['name']}' has no topic — skipping")
        return
    token = config.get("token", "").strip()
    title, body = _build_text_body(event, **kwargs)
    headers = {
        "Title": title,
        "Priority": _NTFY_PRIORITY.get(event, "default"),
        "Content-Type": "text/plain",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(f"{server_url}/{topic}", content=body.encode(), headers=headers)
        r.raise_for_status()


async def _test_ntfy(config: dict) -> tuple[bool, str]:
    server_url = config.get("server_url", "https://ntfy.sh").rstrip("/")
    topic = config.get("topic", "").strip()
    if not topic:
        return False, "No topic configured"
    token = config.get("token", "").strip()
    headers = {
        "Title": "🛡️ Warden — Test",
        "Priority": "default",
        "Content-Type": "text/plain",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(f"{server_url}/{topic}", content=b"Connection test successful.", headers=headers)
        r.raise_for_status()
    return True, f"Message sent to {server_url}/{topic}"


# ── Apprise ────────────────────────────────────────────────────────────────────

_APPRISE_TYPE = {
    "condemned": "warning",
    "reminder": "warning",
    "deleted": "failure",
    "delete_failed": "warning",
    "delete_stuck": "failure",
    "clean_scan": "success",
}

async def _send_apprise(agent: dict, event: str, **kwargs):
    config = json.loads(agent.get("config") or "{}")
    server_url = config.get("server_url", "").rstrip("/")
    if not server_url:
        log.warning(f"Apprise agent '{agent['name']}' has no server URL — skipping")
        return
    if kwargs.get("dry_run"):
        _APPRISE_TYPE["deleted"] = "warning"
    title, body = _build_text_body(event, **kwargs)
    payload: dict = {
        "title": title,
        "body": body,
        "type": _APPRISE_TYPE.get(event, "info"),
    }
    if config.get("tags"):
        payload["tag"] = config["tags"].strip()
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(f"{server_url}/notify", json=payload)
        r.raise_for_status()


async def _test_apprise(config: dict) -> tuple[bool, str]:
    server_url = config.get("server_url", "").rstrip("/")
    if not server_url:
        return False, "No Apprise server URL configured"
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(f"{server_url}/notify", json={
            "title": "🛡️ Warden — Test",
            "body": "Connection test successful.",
            "type": "success",
        })
        r.raise_for_status()
    return True, f"Message sent via Apprise at {server_url}"


# ── JSON Webhook ───────────────────────────────────────────────────────────────

async def _send_webhook(agent: dict, event: str, **kwargs):
    config = json.loads(agent.get("config") or "{}")
    url = config.get("url", "").strip()
    if not url:
        log.warning(f"Webhook agent '{agent['name']}' has no URL — skipping")
        return
    method = config.get("method", "POST").upper()
    extra_headers: dict = {}
    if config.get("headers"):
        try:
            extra_headers = json.loads(config["headers"])
        except Exception:
            pass
    title, body = _build_text_body(event, **kwargs)
    items = kwargs.get("items", [])
    payload = {
        "event": event,
        "title": title,
        "message": body,
        "dry_run": kwargs.get("dry_run", False),
        "count": len(items),
        "items": [
            {
                "title": i.get("title"),
                "year": i.get("year"),
                "media_type": i.get("media_type"),
                "imdb_rating": i.get("imdb_rating"),
                "size_bytes": i.get("size_bytes"),
                "added_date": i.get("added_date"),
                "last_watched_date": i.get("last_watched_date"),
            }
            for i in items
        ],
    }
    if event == "reminder":
        payload["days_remaining"] = kwargs.get("days_remaining")
    if event == "deleted":
        payload["space_freed_bytes"] = kwargs.get("space_freed", 0)
    headers = {"Content-Type": "application/json", **extra_headers}
    async with httpx.AsyncClient(timeout=10) as client:
        if method == "GET":
            r = await client.get(url, params={"payload": json.dumps(payload)}, headers=headers)
        else:
            r = await client.post(url, json=payload, headers=headers)
        r.raise_for_status()


async def _test_webhook(config: dict) -> tuple[bool, str]:
    url = config.get("url", "").strip()
    if not url:
        return False, "No URL configured"
    method = config.get("method", "POST").upper()
    extra_headers: dict = {}
    if config.get("headers"):
        try:
            extra_headers = json.loads(config["headers"])
        except Exception:
            pass
    payload = {"event": "test", "title": "🛡️ Warden — Test", "message": "Connection test successful."}
    headers = {"Content-Type": "application/json", **extra_headers}
    async with httpx.AsyncClient(timeout=10) as client:
        if method == "GET":
            r = await client.get(url, params={"payload": json.dumps(payload)}, headers=headers)
        else:
            r = await client.post(url, json=payload, headers=headers)
        r.raise_for_status()
    return True, f"Request sent to {url}"


# ── Dispatcher ────────────────────────────────────────────────────────────────

_SENDERS = {
    "discord": _send_discord,
    "pushover": _send_pushover,
    "ntfy": _send_ntfy,
    "apprise": _send_apprise,
    "webhook": _send_webhook,
}

_TESTERS = {
    "discord": _test_discord,
    "pushover": _test_pushover,
    "ntfy": _test_ntfy,
    "apprise": _test_apprise,
    "webhook": _test_webhook,
}


async def dispatch(event: str, **kwargs):
    """Fire an event to all enabled agents subscribed to it."""
    from .database import get_notification_agents
    agents = await get_notification_agents(enabled_only=True)
    for agent in agents:
        events = json.loads(agent.get("events") or "[]")
        if event not in events:
            continue
        # For reminder events, only send to agents whose threshold covers this day count
        if event == "reminder":
            days = kwargs.get("days_remaining", 0)
            config = json.loads(agent.get("config") or "{}")
            thresholds = [
                int(x.strip()) for x in (config.get("reminder_days") or "").split(",")
                if x.strip().isdigit()
            ]
            if thresholds and days not in thresholds:
                continue
        sender = _SENDERS.get(agent["agent_type"])
        if not sender:
            log.warning(f"Unknown agent type '{agent['agent_type']}' for agent '{agent['name']}'")
            continue
        try:
            await sender(agent, event, **kwargs)
        except Exception as e:
            log.error(f"Agent '{agent['name']}' failed for event '{event}': {e}")


async def test_agent(agent: dict) -> tuple[bool, str]:
    """Send a test notification. Returns (success, detail_message)."""
    config = json.loads(agent.get("config") or "{}")
    tester = _TESTERS.get(agent.get("agent_type", ""))
    if not tester:
        return False, f"Unknown agent type: {agent.get('agent_type')}"
    try:
        return await tester(config)
    except Exception as e:
        return False, str(e)[:200]
