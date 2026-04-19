import base64
import json
import logging
import time
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from .. import webauthn_helper as _wh

from ..auth import (
    hash_password, verify_password,
    generate_totp_secret, get_totp_uri, verify_totp,
    generate_backup_codes, hash_backup_code, verify_and_consume_backup_code,
)
from ..config import get_config_async
from ..database import (
    get_stats, get_recent_scan_runs,
    get_report_library_stats, get_report_deletion_totals,
    get_report_age_buckets, get_report_watch_stats, get_report_top_condemned,
    get_report_timeline_data,
    get_media_items, get_media_item,
    pardon_item, unpardon_item, expedite_item, get_rules, get_rule, upsert_rule, delete_rule,
    get_all_settings, get_setting, set_setting, set_settings_bulk, get_library_page,
    get_notification_agents, get_notification_agent,
    upsert_notification_agent, delete_notification_agent,
    log_audit, get_audit_log,
    get_auth_username, set_auth_username,
    get_auth_password_hash, set_auth_password_hash,
    is_totp_enabled, get_totp_secret, enable_totp, disable_totp,
    get_totp_backup_hashes, set_totp_backup_hashes,
    export_config, import_config, _full_backup_sync,
    get_passkeys, add_passkey, get_passkey_by_credential_id,
    update_passkey_sign_count, delete_passkey,
)
from ..scanner import run_scan, is_running
from ..sources.radarr import RadarrClient
from ..sources.sonarr import SonarrClient

log = logging.getLogger(__name__)

# ── Login rate limiting ────────────────────────────────────────────────────────
_login_attempts: dict[str, list[float]] = defaultdict(list)
_RATE_LIMIT_MAX  = 5   # failed attempts
_RATE_LIMIT_SECS = 60  # sliding window


def _is_rate_limited(ip: str) -> bool:
    now = time.monotonic()
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < _RATE_LIMIT_SECS]
    return len(_login_attempts[ip]) >= _RATE_LIMIT_MAX


def _record_failure(ip: str):
    _login_attempts[ip].append(time.monotonic())


def _clear_failures(ip: str):
    _login_attempts.pop(ip, None)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.filters["from_json"] = json.loads


# ── Auth exceptions (handled in main.py) ──────────────────────────────────────

class NeedsSetup(Exception):
    """Raised when no admin password has been configured yet."""


class NotAuthenticated(Exception):
    """Raised when the user is not logged in."""


async def require_auth(request: Request):
    """FastAPI dependency that enforces authentication on every protected route."""
    pw_hash = await get_auth_password_hash()
    if not pw_hash:
        raise NeedsSetup()
    if not request.session.get("authenticated"):
        raise NotAuthenticated()


# ── Auth router (no authentication required) ──────────────────────────────────

auth_router = APIRouter()


@auth_router.get("/setup", response_class=HTMLResponse)
async def setup_get(request: Request):
    pw_hash = await get_auth_password_hash()
    if pw_hash:
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse("setup.html", {"request": request, "error": None})


@auth_router.post("/setup", response_class=HTMLResponse)
async def setup_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm: str = Form(...),
):
    pw_hash = await get_auth_password_hash()
    if pw_hash:
        return RedirectResponse("/", status_code=302)
    error = None
    if not username.strip():
        error = "Username is required."
    elif len(password) < 8:
        error = "Password must be at least 8 characters."
    elif password != confirm:
        error = "Passwords do not match."
    if error:
        return templates.TemplateResponse("setup.html", {"request": request, "error": error, "username": username})
    await set_auth_username(username.strip())
    await set_auth_password_hash(hash_password(password))
    request.session["authenticated"] = True
    request.session["username"] = username.strip()
    return RedirectResponse("/", status_code=302)


@auth_router.get("/login", response_class=HTMLResponse)
async def login_get(request: Request, next: str = "/"):
    if request.session.get("authenticated"):
        return RedirectResponse(next or "/", status_code=302)
    pw_hash = await get_auth_password_hash()
    if not pw_hash:
        return RedirectResponse("/setup", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "next": next, "username_value": "", "error": None})


@auth_router.post("/login", response_class=HTMLResponse)
async def login_post(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form(default="/")):
    ip = request.client.host
    if _is_rate_limited(ip):
        return templates.TemplateResponse("login.html", {
            "request": request, "next": next, "username_value": username,
            "error": "Too many failed attempts. Please wait a minute and try again.",
        }, status_code=429)
    pw_hash = await get_auth_password_hash()
    if not pw_hash:
        return RedirectResponse("/setup", status_code=302)
    stored_username = await get_auth_username()
    def _error_resp():
        _record_failure(ip)
        return templates.TemplateResponse("login.html", {
            "request": request, "next": next, "username_value": username, "error": "Incorrect username or password."
        })
    if username.strip().lower() != (stored_username or "").strip().lower():
        return _error_resp()
    if not verify_password(password, pw_hash):
        return _error_resp()
    # Credentials OK — check if TOTP is required.
    _clear_failures(ip)
    username = stored_username
    if await is_totp_enabled():
        request.session["pw_verified"] = True
        request.session["totp_next"] = next or "/"
        request.session["pending_username"] = username
        return RedirectResponse("/login/totp", status_code=302)
    request.session["authenticated"] = True
    request.session["username"] = username
    return RedirectResponse(next or "/", status_code=302)


@auth_router.get("/login/totp", response_class=HTMLResponse)
async def totp_login_get(request: Request):
    if not request.session.get("pw_verified"):
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("totp_login.html", {"request": request, "error": None})


@auth_router.post("/login/totp", response_class=HTMLResponse)
async def totp_login_post(request: Request, code: str = Form(...)):
    if not request.session.get("pw_verified"):
        return RedirectResponse("/login", status_code=302)
    ip = request.client.host
    if _is_rate_limited(ip):
        return templates.TemplateResponse("totp_login.html", {
            "request": request, "error": "Too many failed attempts. Please wait a minute and try again.",
        }, status_code=429)
    secret = await get_totp_secret()
    if secret and verify_totp(secret, code):
        _clear_failures(ip)
        request.session.pop("pw_verified", None)
        next_url = request.session.pop("totp_next", "/")
        request.session["username"] = request.session.pop("pending_username", "Admin")
        request.session["authenticated"] = True
        return RedirectResponse(next_url or "/", status_code=302)
    _record_failure(ip)
    return templates.TemplateResponse("totp_login.html", {"request": request, "error": "Invalid code. Please try again."})


@auth_router.get("/login/backup", response_class=HTMLResponse)
async def backup_login_get(request: Request):
    if not request.session.get("pw_verified"):
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("totp_backup_login.html", {"request": request, "error": None})


@auth_router.post("/login/backup", response_class=HTMLResponse)
async def backup_login_post(request: Request, backup_code: str = Form(...)):
    if not request.session.get("pw_verified"):
        return RedirectResponse("/login", status_code=302)
    ip = request.client.host
    if _is_rate_limited(ip):
        return templates.TemplateResponse("totp_backup_login.html", {
            "request": request, "error": "Too many failed attempts. Please wait a minute and try again.",
        }, status_code=429)
    hashes = await get_totp_backup_hashes()
    matched, remaining = verify_and_consume_backup_code(backup_code, hashes)
    if matched:
        _clear_failures(ip)
        await set_totp_backup_hashes(remaining)
        request.session.pop("pw_verified", None)
        next_url = request.session.pop("totp_next", "/")
        request.session["username"] = request.session.pop("pending_username", "Admin")
        request.session["authenticated"] = True
        return RedirectResponse(next_url or "/", status_code=302)
    _record_failure(ip)
    return templates.TemplateResponse("totp_backup_login.html", {"request": request, "error": "Invalid backup code."})


@auth_router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


# ── Passkey authentication (unprotected) ──────────────────────────────────────

@auth_router.get("/login/passkey/begin")
async def passkey_login_begin(request: Request, next: str = "/"):
    rp_id = (await get_setting("webauthn_rp_id") or "").strip()
    if not rp_id:
        return JSONResponse({"error": "Passkeys are not configured on this server."}, status_code=400)
    request.session["passkey_next"] = next or "/"
    options, challenge = _wh.generate_authentication_options(rp_id=rp_id)
    request.session["passkey_auth_challenge"] = _b64url_encode(challenge)
    return JSONResponse(options)


@auth_router.post("/login/passkey/complete")
async def passkey_login_complete(request: Request):
    ip = request.client.host
    if _is_rate_limited(ip):
        return JSONResponse({"error": "Too many failed attempts. Please wait a minute and try again."}, status_code=429)
    challenge_b64 = request.session.pop("passkey_auth_challenge", None)
    if not challenge_b64:
        return JSONResponse({"error": "Session expired. Please try again."}, status_code=400)
    rp_id = (await get_setting("webauthn_rp_id") or "").strip()
    if not rp_id:
        return JSONResponse({"error": "Passkeys not configured."}, status_code=400)
    try:
        body = await request.json()
        raw_id = _b64url_decode(body["rawId"])
        passkey = await get_passkey_by_credential_id(raw_id)
        if not passkey:
            _record_failure(ip)
            return JSONResponse({"error": "Passkey not recognised."}, status_code=400)
        verification = _wh.verify_authentication_response(
            credential=body,
            expected_challenge=_b64url_decode(challenge_b64),
            expected_rp_id=rp_id,
            expected_origin=f"https://{rp_id}",
            credential_public_key=passkey["public_key"],
            credential_current_sign_count=passkey["sign_count"],
        )
        await update_passkey_sign_count(raw_id, verification.new_sign_count)
        _clear_failures(ip)
        username = await get_auth_username()
        request.session["authenticated"] = True
        request.session["username"] = username
        next_url = request.session.pop("passkey_next", "/")
        await log_audit("Passkey login", ip=request.client.host)
        return JSONResponse({"ok": True, "redirect": next_url or "/"})
    except Exception as e:
        _record_failure(ip)
        log.warning("Passkey auth failed: %s", e)
        return JSONResponse({"error": "Authentication failed."}, status_code=400)


# ── Favicon ───────────────────────────────────────────────────────────────────

@auth_router.get("/favicon.svg")
async def favicon():
    svg = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <path d="M16 2L29 7v10c0 7.5-5.5 13.5-13 15C4.5 30.5 3 24.5 3 17V7z" fill="#e74c3c"/>
  <polyline points="9,13 12,22 16,17 20,22 23,13"
    fill="none" stroke="white" stroke-width="2.5"
    stroke-linejoin="round" stroke-linecap="round"/>
</svg>"""
    return Response(content=svg, media_type="image/svg+xml")


# ── Protected router ───────────────────────────────────────────────────────────

router = APIRouter(dependencies=[Depends(require_auth)])


def _cron_to_friendly(cron: str) -> dict:
    """
    Parse a simple cron expression into friendly form fields.
    Returns dict with keys: interval, unit, time (HH:MM string).
    Falls back gracefully for unsupported patterns.
    """
    try:
        parts = cron.strip().split()
        if len(parts) != 5:
            return {"interval": 1, "unit": "days", "time": "08:00"}
        minute, hour, dom, month, dow = parts
        if month != "*":
            return {"interval": 1, "unit": "days", "time": "08:00"}
        time_str = f"{int(hour):02d}:{int(minute):02d}"
        if dom == "*" and dow == "*":
            return {"interval": 1, "unit": "days", "time": time_str}
        if dom.startswith("*/") and dow == "*":
            n = int(dom[2:])
            if n % 7 == 0:
                return {"interval": n // 7, "unit": "weeks", "time": time_str}
            return {"interval": n, "unit": "days", "time": time_str}
    except Exception:
        pass
    return {"interval": 1, "unit": "days", "time": "08:00"}


def _friendly_to_cron(interval: int, unit: str, time: str) -> str:
    """Convert friendly schedule fields back to a cron expression."""
    try:
        hh, mm = time.split(":")
        hour, minute = int(hh), int(mm)
    except Exception:
        hour, minute = 8, 0
    interval = max(1, int(interval))
    if unit == "weeks":
        days = interval * 7
        if days == 7:
            return f"{minute} {hour} * * *"  # daily equivalent for 1 week
        return f"{minute} {hour} */{days} * *"
    # days
    if interval == 1:
        return f"{minute} {hour} * * *"
    return f"{minute} {hour} */{interval} * *"


def _days_left(item: dict, death_row_days: int) -> int | None:
    if not item.get("death_row_date"):
        return None
    try:
        drd = date.fromisoformat(item["death_row_date"])
        delete_on = drd + timedelta(days=death_row_days)
        return max(0, (delete_on - date.today()).days)
    except Exception:
        return None


def _format_size(size_bytes: int | None) -> str:
    if not size_bytes:
        return "—"
    gb = size_bytes / 1_073_741_824
    return f"{gb:,.1f} GB"


def _parse_date(date_str: str) -> date:
    """Parse a date or datetime ISO string to a date object."""
    try:
        return date.fromisoformat(date_str)
    except ValueError:
        return datetime.fromisoformat(date_str).date()


def _format_age(date_str: str | None) -> str:
    if not date_str:
        return "—"
    try:
        d = _parse_date(date_str)
        days = (date.today() - d).days
        if days < 30:
            return f"{days}d ago"
        elif days < 365:
            return f"{days // 30}mo ago"
        else:
            return f"{days // 365}yr ago"
    except Exception:
        return "—"


def _format_scan_time(dt_str: str | None, tz_name: str = "UTC") -> str:
    """Format a scan timestamp as 'Today HH:MM', 'Yesterday HH:MM', or 'D Mon HH:MM' in the configured timezone."""
    if not dt_str:
        return "Never"
    try:
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
        try:
            tz = ZoneInfo(tz_name)
        except ZoneInfoNotFoundError:
            tz = ZoneInfo("UTC")
        dt = datetime.fromisoformat(dt_str).astimezone(tz)
        today = datetime.now(tz).date()
        d = dt.date()
        time_str = dt.strftime("%H:%M")
        if d == today:
            return f"Today {time_str}"
        elif d == today - timedelta(days=1):
            return f"Yesterday {time_str}"
        else:
            return dt.strftime("%-d %b %H:%M")
    except Exception:
        return "—"


# ── Dashboard ─────────────────────────────────────────────────────────────────

@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    stats = await get_stats()
    runs = await get_recent_scan_runs(5)
    settings = await get_all_settings()
    tz = settings.get("timezone") or "UTC"
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "stats": stats,
        "runs": runs,
        "settings": settings,
        "scanning": is_running(),
        "format_size": _format_size,
        "format_age": _format_age,
        "format_scan_time": lambda dt_str: _format_scan_time(dt_str, tz),
    })


@router.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request):
    import asyncio
    settings = await get_all_settings()
    tz = settings.get("timezone") or "UTC"
    (lib_stats, del_totals, age_buckets,
     watch_stats, top_condemned, timeline_data) = await asyncio.gather(
        get_report_library_stats(),
        get_report_deletion_totals(),
        get_report_age_buckets(),
        get_report_watch_stats(),
        get_report_top_condemned(5),
        get_report_timeline_data(),
    )
    bucket_pairs = [
        ("< 1 yr",    age_buckets.get("under_1yr") or 0),
        ("1 – 2 yrs", age_buckets.get("yr_1_2") or 0),
        ("2 – 3 yrs", age_buckets.get("yr_2_3") or 0),
        ("3 – 5 yrs", age_buckets.get("yr_3_5") or 0),
        ("5 yrs+",    age_buckets.get("over_5yr") or 0),
    ]
    bucket_total = sum(c for _, c in bucket_pairs) or 1
    age_data = [(lbl, cnt, round(cnt / bucket_total * 100)) for lbl, cnt in bucket_pairs]

    for item in top_condemned:
        try:
            rules = json.loads(item["criteria_matched"] or "[]")
            item["rule_name"] = rules[0] if rules else "—"
        except Exception:
            item["rule_name"] = "—"
        item["size_fmt"] = _format_size(item.get("size_bytes"))

    total_active = (watch_stats.get("watched_count") or 0) + (watch_stats.get("unwatched_count") or 0)
    watch_pct = round((watch_stats.get("watched_count") or 0) / (total_active or 1) * 100)

    return templates.TemplateResponse("reports.html", {
        "request": request, "settings": settings,
        "lib_stats": lib_stats, "del_totals": del_totals,
        "age_data": age_data,
        "watch_stats": watch_stats, "watch_pct": watch_pct,
        "top_condemned": top_condemned,
        "timeline_json": json.dumps(timeline_data),
        "format_size": _format_size,
    })


@router.post("/scan/run", response_class=HTMLResponse)
async def trigger_scan(request: Request):
    if not is_running():
        import asyncio
        asyncio.create_task(run_scan())
        await log_audit("Manual scan triggered", ip=request.client.host)
    return HTMLResponse('<span class="scanning">Scan started...</span>')


# ── Death Row ─────────────────────────────────────────────────────────────────

_DEATH_ROW_SORTS = {"title", "imdb_rating", "days_left", "added_date", "last_watched_date", "size_bytes"}


_FIELD_NULL_SENTINEL = {
    "last_watched_date": "",           # NULL = never watched = oldest
    "added_date":        "9999-12-31",
    "death_row_date":    "9999-12-31",
    "imdb_rating":       999_999,
    "total_plays":       999_999,
    "size_bytes":        999_999_999_999,
    "days_left":         999_999,
}


def _sort_null_last(items: list, field: str, order: str) -> list:
    """Sort items, treating null as the sentinel value for its field."""
    sentinel = _FIELD_NULL_SENTINEL.get(field, "9999-12-31")

    def key(x):
        v = x.get(field)
        if v is None:
            return sentinel
        return v.lower() if isinstance(v, str) else v

    return sorted(items, key=key, reverse=(order == "desc"))


@router.get("/death-row", response_class=HTMLResponse)
async def death_row(request: Request, sort: str = "days_left", order: str = "asc"):
    settings = await get_all_settings()
    death_row_days = int(settings.get("death_row_days", 30))

    condemned = await get_media_items(status="condemned")

    for item in condemned:
        item["days_left"] = _days_left(item, death_row_days)
        item["size_fmt"] = _format_size(item.get("size_bytes"))
        item["added_fmt"] = _format_age(item.get("added_date"))
        item["watched_fmt"] = _format_age(item.get("last_watched_date")) if item.get("last_watched_date") else "Never"

    if sort not in _DEATH_ROW_SORTS:
        sort = "days_left"
    condemned = _sort_null_last(condemned, sort, order)

    def sort_url(field: str) -> str:
        new_order = "desc" if (sort == field and order == "asc") else "asc"
        return f"/death-row?sort={field}&order={new_order}"

    return templates.TemplateResponse("death_row.html", {
        "request": request,
        "items": condemned,
        "settings": settings,
        "total_size": _format_size(sum(i.get("size_bytes") or 0 for i in condemned)),
        "sort": sort,
        "order": order,
        "sort_url": sort_url,
    })


@router.post("/death-row/bulk", response_class=HTMLResponse)
async def bulk_death_row_action(request: Request):
    form = await request.form()
    action = form.get("action")
    ids = form.getlist("ids")
    settings = await get_all_settings()

    if not ids:
        return RedirectResponse("/death-row", status_code=303)

    if action == "expedite":
        expedite_days_str = (settings.get("expedite_days") or "").strip()
        if not expedite_days_str:
            return RedirectResponse("/death-row?bulk_error=expedite_not_configured", status_code=303)
        death_row_days = int(settings.get("death_row_days", 30))
        exp_days = max(1, min(int(expedite_days_str), death_row_days - 1))
        offset = death_row_days - exp_days
        new_drd = (date.today() - timedelta(days=offset)).isoformat()
        for item_id in ids:
            await expedite_item(item_id, new_drd, exp_days)
        await log_audit("Bulk expedite", f"{len(ids)} items — {exp_days}d remaining", request.client.host)

    elif action == "pardon":
        reason = form.get("bulk_reason", "").strip() or "Bulk pardon"
        for item_id in ids:
            await pardon_item(item_id, reason)
        await log_audit("Bulk pardon", f"{len(ids)} items — {reason}", request.client.host)

    return RedirectResponse("/death-row", status_code=303)


@router.post("/death-row/{item_id}/expedite", response_class=HTMLResponse)
async def expedite(request: Request, item_id: str):
    settings = await get_all_settings()
    expedite_days_str = (settings.get("expedite_days") or "").strip()
    if not expedite_days_str:
        return HTMLResponse(
            '<td colspan="9" style="color:var(--accent)">'
            'Expedite Days not configured — set it in <a href="/settings">Settings</a> first.'
            '</td>'
        )
    death_row_days = int(settings.get("death_row_days", 30))
    exp_days = max(1, min(int(expedite_days_str), death_row_days - 1))
    offset = death_row_days - exp_days
    new_drd = (date.today() - timedelta(days=offset)).isoformat()
    await expedite_item(item_id, new_drd, exp_days)
    item = await get_media_item(item_id)
    title = item["title"] if item else item_id
    await log_audit("Item expedited", f"{title} — {exp_days}d remaining", request.client.host)
    return HTMLResponse(
        f'<td colspan="9" style="color:var(--accent)">'
        f'Execution expedited — {exp_days} day{"s" if exp_days != 1 else ""} remaining'
        f'</td>'
    )


@router.post("/death-row/{item_id}/pardon", response_class=HTMLResponse)
async def pardon(request: Request, item_id: str, reason: str = Form(...)):
    item = await get_media_item(item_id)
    await pardon_item(item_id, reason)
    title = item["title"] if item else item_id
    await log_audit("Item pardoned", f"{title} — {reason}" if reason else title, request.client.host)
    return HTMLResponse('<tr><td colspan="9" class="pardoned">✓ Pardoned</td></tr>')


# ── Candidates ────────────────────────────────────────────────────────────────

_CANDIDATES_SORTS = {"title", "imdb_rating", "size_bytes", "added_date", "last_watched_date", "total_plays"}


@router.get("/candidates", response_class=HTMLResponse)
async def candidates(request: Request, sort: str = "title", order: str = "asc"):
    settings = await get_all_settings()
    all_candidates = await get_media_items(status="condemned")

    if sort not in _CANDIDATES_SORTS:
        sort = "title"

    # Group by first matched rule
    by_rule: dict[str, list] = {}
    for item in all_candidates:
        rules = item.get("criteria_matched") or ["Unknown"]
        rule = rules[0]
        item["size_fmt"] = _format_size(item.get("size_bytes"))
        item["added_fmt"] = _format_age(item.get("added_date"))
        item["watched_fmt"] = _format_age(item.get("last_watched_date")) if item.get("last_watched_date") else "Never"
        by_rule.setdefault(rule, []).append(item)

    # Sort items within each group
    for items in by_rule.values():
        items[:] = _sort_null_last(items, sort, order)

    total_size = sum(i.get("size_bytes") or 0 for i in all_candidates)

    def sort_url(field: str) -> str:
        new_order = "desc" if (sort == field and order == "asc") else "asc"
        return f"/candidates?sort={field}&order={new_order}"

    return templates.TemplateResponse("candidates.html", {
        "request": request,
        "by_rule": by_rule,
        "total_count": len(all_candidates),
        "total_size": _format_size(total_size),
        "settings": settings,
        "sort": sort,
        "order": order,
        "sort_url": sort_url,
    })


# ── Library ───────────────────────────────────────────────────────────────────

PER_PAGE = 100

@router.get("/library", response_class=HTMLResponse)
async def library(
    request: Request,
    q: str = "",
    media_type: str = "",
    status: str = "",
    watched: str = "",
    sort: str = "title",
    order: str = "asc",
    page: int = 1,
):
    settings = await get_all_settings()
    items, total = await get_library_page(
        q=q, media_type=media_type, status=status, watched=watched,
        sort=sort, order=order, page=page, per_page=PER_PAGE,
    )
    for item in items:
        item["size_fmt"] = _format_size(item.get("size_bytes"))
        item["added_fmt"] = _format_age(item.get("added_date"))
        item["watched_fmt"] = _format_age(item.get("last_watched_date")) if item.get("last_watched_date") else "Never"

    total_pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)

    def sort_url(field):
        new_order = "desc" if (sort == field and order == "asc") else "asc"
        return f"/library?q={q}&media_type={media_type}&status={status}&watched={watched}&sort={field}&order={new_order}&page=1"

    return templates.TemplateResponse("library.html", {
        "request": request,
        "items": items,
        "total": total,
        "page": page,
        "total_pages": total_pages,
        "q": q,
        "media_type": media_type,
        "status": status,
        "watched": watched,
        "sort": sort,
        "order": order,
        "settings": settings,
        "sort_url": sort_url,
    })


# ── Library Item Detail ───────────────────────────────────────────────────────

@router.get("/library/{item_id}", response_class=HTMLResponse)
async def library_item(request: Request, item_id: str):
    item = await get_media_item(item_id)
    if not item:
        return HTMLResponse("Not found", status_code=404)

    settings = await get_all_settings()
    death_row_days = int(settings.get("death_row_days", 30))
    cfg = await get_config_async()

    arr_detail = {}
    if item["status"] != "deleted":
        try:
            if item["media_type"] == "movie":
                arr_detail = await RadarrClient(cfg.radarr.url, cfg.radarr.api_key).get_movie_detail(item["arr_id"])
            else:
                arr_detail = await SonarrClient(cfg.sonarr.url, cfg.sonarr.api_key).get_series_detail(item["arr_id"])
        except Exception as e:
            log.warning(f"Could not fetch arr detail for {item_id}: {e}")

    # Build external links — skipped for deleted items (no longer in Radarr/Sonarr/Plex)
    links = {}
    if item["status"] != "deleted":
        imdb_id = arr_detail.get("imdb_id") or item.get("imdb_id")
        title_slug = arr_detail.get("title_slug", "")
        if imdb_id:
            links["IMDb"] = f"https://www.imdb.com/title/{imdb_id}"
        if item["media_type"] == "movie" and arr_detail.get("tmdb_id"):
            links["TMDB"] = f"https://www.themoviedb.org/movie/{arr_detail['tmdb_id']}"
        if item["media_type"] == "show" and arr_detail.get("tvdb_id"):
            links["TVDB"] = f"https://www.thetvdb.com/series/{title_slug or arr_detail['tvdb_id']}"
        radarr_base = (cfg.radarr.public_url or cfg.radarr.url).rstrip("/")
        sonarr_base = (cfg.sonarr.public_url or cfg.sonarr.url).rstrip("/")
        if item["media_type"] == "movie" and radarr_base:
            links["Radarr"] = f"{radarr_base}/movie/{title_slug}"
        elif item["media_type"] == "show" and sonarr_base:
            links["Sonarr"] = f"{sonarr_base}/series/{title_slug}"
        plex_rating_key = item.get("plex_rating_key")
        plex_machine_id = await get_setting("plex_machine_id")
        if plex_rating_key and plex_machine_id:
            plex_base = (cfg.plex.public_url or "https://app.plex.tv").rstrip("/")
            links["Plex"] = (
                f"{plex_base}/desktop/#!/server/{plex_machine_id}"
                f"/details?key=%2Flibrary%2Fmetadata%2F{plex_rating_key}"
            )
        elif cfg.plex.public_url or cfg.plex.url:
            links["Plex"] = cfg.plex.public_url or cfg.plex.url

    return templates.TemplateResponse("library_item.html", {
        "request": request,
        "item": item,
        "arr": arr_detail,
        "links": links,
        "settings": settings,
        "days_left": _days_left(item, death_row_days),
        "format_size": _format_size,
        "format_age": _format_age,
    })


@router.post("/library/{item_id}/pardon", response_class=HTMLResponse)
async def library_item_pardon(request: Request, item_id: str, reason: str = Form(...)):
    item = await get_media_item(item_id)
    await pardon_item(item_id, reason)
    title = item["title"] if item else item_id
    await log_audit("Item pardoned", f"{title} — {reason}" if reason else title, request.client.host)
    return RedirectResponse(f"/library/{item_id}", status_code=303)


@router.post("/library/{item_id}/unpardon", response_class=HTMLResponse)
async def library_item_unpardon(request: Request, item_id: str):
    item = await get_media_item(item_id)
    await unpardon_item(item_id)
    title = item["title"] if item else item_id
    await log_audit("Item unpardoned", title, request.client.host)
    return RedirectResponse(f"/library/{item_id}", status_code=303)


# ── Settings ──────────────────────────────────────────────────────────────────

def _get_timezones() -> dict[str, list[str]]:
    """Return IANA timezones grouped by region for use in a select dropdown."""
    from zoneinfo import available_timezones
    grouped: dict[str, list[str]] = {}
    for tz in sorted(available_timezones()):
        region = tz.split("/")[0] if "/" in tz else "Other"
        grouped.setdefault(region, []).append(tz)
    for region in grouped:
        grouped[region].sort()
    return dict(sorted(grouped.items()))


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    settings = await get_all_settings()
    schedule_friendly = _cron_to_friendly(settings.get("schedule", "0 8 * * *"))
    agents = await get_notification_agents()
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "settings": settings,
        "schedule_friendly": schedule_friendly,
        "timezones": _get_timezones(),
        "agents": agents,
    })


async def _settings_response(request: Request, saved: bool = False, **extra):
    settings = await get_all_settings()
    agents = await get_notification_agents()
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "settings": settings,
        "schedule_friendly": _cron_to_friendly(settings.get("schedule", "0 8 * * *")),
        "timezones": _get_timezones(),
        "agents": agents,
        "saved": saved,
        **extra,
    })


@router.post("/settings", response_class=HTMLResponse)
async def save_settings(request: Request):
    form = await request.form()
    await log_audit("General settings saved", ip=request.client.host)

    interval = form.get("schedule_interval", "1")
    unit = form.get("schedule_unit", "days")
    time_val = form.get("schedule_time", "08:00")
    new_schedule = _friendly_to_cron(int(interval or 1), unit, time_val)

    pairs: dict[str, str] = {
        "dry_run": "true" if form.get("dry_run") == "true" else "false",
        "schedule": new_schedule,
    }
    for key in ("watch_threshold_percent", "tv_watched_definition", "death_row_days", "expedite_days", "timezone"):
        value = form.get(key)
        if value is not None:
            pairs[key] = str(value)
    rp_id = form.get("webauthn_rp_id")
    if rp_id is not None:
        pairs["webauthn_rp_id"] = str(rp_id).strip().lower()

    await set_settings_bulk(pairs)

    from ..main import reschedule
    await reschedule(new_schedule)

    settings = await get_all_settings()
    agents = await get_notification_agents()
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "settings": settings,
        "schedule_friendly": _cron_to_friendly(new_schedule),
        "timezones": _get_timezones(),
        "agents": agents,
        "saved": True,
    })


@router.post("/settings/connections", response_class=HTMLResponse)
async def save_connections(request: Request):
    form = await request.form()
    await log_audit("Connection settings saved", ip=request.client.host)

    pairs = {
        key: str(form.get(key, ""))
        for key in (
            "radarr_url", "radarr_api_key", "radarr_public_url",
            "sonarr_url", "sonarr_api_key", "sonarr_public_url",
            "plex_url", "plex_token", "plex_public_url",
            "tautulli_url", "tautulli_api_key", "tautulli_public_url",
        )
        if form.get(key) is not None
    }
    await set_settings_bulk(pairs)

    return await _settings_response(request, saved=True)


@router.post("/settings/notifications", response_class=HTMLResponse)
async def save_notifications(request: Request):
    form = await request.form()
    value = form.get("reminder_days")
    if value is not None:
        await set_setting("reminder_days", str(value))
    return await _settings_response(request, saved=True)


# ── Connection tests ──────────────────────────────────────────────────────────

def _test_badge(ok: bool, detail: str) -> str:
    color = "var(--safe)" if ok else "var(--danger)"
    icon = "✓" if ok else "✗"
    return f'<span style="color:{color};font-size:0.85rem">{icon} {detail}</span>'


@router.post("/settings/test/radarr", response_class=HTMLResponse)
async def test_radarr():
    import httpx
    cfg = await get_config_async()
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                f"{cfg.radarr.url.rstrip('/')}/api/v3/system/status",
                headers={"X-Api-Key": cfg.radarr.api_key},
            )
            r.raise_for_status()
            data = r.json()
        return _test_badge(True, f"Connected — Radarr v{data.get('version', '?')}")
    except Exception as e:
        return _test_badge(False, str(e)[:80])


@router.post("/settings/test/sonarr", response_class=HTMLResponse)
async def test_sonarr():
    import httpx
    cfg = await get_config_async()
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                f"{cfg.sonarr.url.rstrip('/')}/api/v3/system/status",
                headers={"X-Api-Key": cfg.sonarr.api_key},
            )
            r.raise_for_status()
            data = r.json()
        return _test_badge(True, f"Connected — Sonarr v{data.get('version', '?')}")
    except Exception as e:
        return _test_badge(False, str(e)[:80])


@router.post("/settings/test/plex", response_class=HTMLResponse)
async def test_plex():
    import httpx
    cfg = await get_config_async()
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                cfg.plex.url.rstrip("/"),
                headers={"X-Plex-Token": cfg.plex.token, "Accept": "application/json"},
            )
            r.raise_for_status()
            data = r.json()
        mc = data.get("MediaContainer", {})
        name = mc.get("friendlyName") or mc.get("title1") or "Plex"
        version = mc.get("version", "?")
        return _test_badge(True, f"Connected — {name} v{version}")
    except Exception as e:
        return _test_badge(False, str(e)[:80])


@router.post("/settings/test/tautulli", response_class=HTMLResponse)
async def test_tautulli():
    import httpx
    cfg = await get_config_async()
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                f"{cfg.tautulli.url.rstrip('/')}/api/v2",
                params={"apikey": cfg.tautulli.api_key, "cmd": "get_server_info"},
            )
            r.raise_for_status()
            data = r.json()
        info = data.get("response", {}).get("data", {})
        name = info.get("pms_name") or "Tautulli"
        return _test_badge(True, f"Connected — {name}")
    except Exception as e:
        return _test_badge(False, str(e)[:80])


@router.post("/settings/notifications/agents/{agent_id}/test", response_class=HTMLResponse)
async def test_notification_agent(agent_id: int):
    from ..notifications import test_agent
    agent = await get_notification_agent(agent_id)
    if not agent:
        return _test_badge(False, "Agent not found")
    ok, detail = await test_agent(agent)
    return _test_badge(ok, detail)


# ── Notification agents ───────────────────────────────────────────────────────

AGENT_TYPES = {
    "discord":  {"label": "Discord",      "icon": "🎮", "desc": "Webhook-based messages with rich embeds"},
    "pushover": {"label": "Pushover",     "icon": "📱", "desc": "Push notifications via the Pushover service"},
    "ntfy":     {"label": "ntfy",         "icon": "📢", "desc": "Self-hostable push notifications via ntfy.sh"},
    "apprise":  {"label": "Apprise",      "icon": "🔔", "desc": "100+ services via a self-hosted Apprise API server"},
    "webhook":  {"label": "JSON Webhook", "icon": "🔗", "desc": "POST raw JSON to any custom HTTP endpoint"},
}

ALL_EVENTS = [
    ("condemned",     "🚨", "New items condemned"),
    ("reminder",      "⏳", "Death row reminders"),
    ("deleted",       "🗑️",  "Items executed"),
    ("delete_failed", "⚠️",  "Deletions failed (will retry)"),
    ("delete_stuck",  "🛑", "Deletions stuck (manual attention)"),
    ("clean_scan",    "✅", "Clean scan"),
    ("scan_error",    "⚠️",  "Scan failed"),
]


@router.get("/settings/notifications/agents/new", response_class=HTMLResponse)
async def new_agent_type(request: Request):
    settings = await get_all_settings()
    agent_type = request.query_params.get("type", "")
    if agent_type and agent_type in AGENT_TYPES:
        return templates.TemplateResponse("notification_agent_form.html", {
            "request": request,
            "agent": {"agent_type": agent_type},
            "action": "/settings/notifications/agents/create",
            "agent_types": AGENT_TYPES,
            "all_events": ALL_EVENTS,
            "settings": settings,
        })
    return templates.TemplateResponse("notification_agent_type.html", {
        "request": request,
        "agent_types": AGENT_TYPES,
        "settings": settings,
    })


@router.post("/settings/notifications/agents/create")
async def create_agent(request: Request):
    form = await request.form()
    agent = _form_to_agent(form)
    await upsert_notification_agent(agent)
    await log_audit("Notification agent created", agent["name"], request.client.host)
    return RedirectResponse("/settings#notifications", status_code=303)


@router.get("/settings/notifications/agents/{agent_id}/edit", response_class=HTMLResponse)
async def edit_agent(request: Request, agent_id: int):
    agent = await get_notification_agent(agent_id)
    if not agent:
        return RedirectResponse("/settings#notifications", status_code=303)
    settings = await get_all_settings()
    # Decode config so template can access individual fields
    agent["config_dict"] = json.loads(agent.get("config") or "{}")
    agent["events_list"] = json.loads(agent.get("events") or "[]")
    return templates.TemplateResponse("notification_agent_form.html", {
        "request": request,
        "agent": agent,
        "action": f"/settings/notifications/agents/{agent_id}/update",
        "agent_types": AGENT_TYPES,
        "all_events": ALL_EVENTS,
        "settings": settings,
    })


@router.post("/settings/notifications/agents/{agent_id}/update")
async def update_agent(request: Request, agent_id: int):
    form = await request.form()
    agent = _form_to_agent(form)
    agent["id"] = agent_id
    await upsert_notification_agent(agent)
    await log_audit("Notification agent updated", agent["name"], request.client.host)
    return RedirectResponse("/settings#notifications", status_code=303)


@router.post("/settings/notifications/agents/{agent_id}/toggle", response_class=HTMLResponse)
async def toggle_agent(request: Request, agent_id: int):
    agent = await get_notification_agent(agent_id)
    if agent:
        agent["enabled"] = 0 if agent["enabled"] else 1
        await upsert_notification_agent(agent)
        state = "enabled" if agent["enabled"] else "disabled"
        await log_audit(f"Notification agent {state}", agent["name"], request.client.host)
    return RedirectResponse("/settings#notifications", status_code=303)


@router.post("/settings/notifications/agents/{agent_id}/delete", response_class=HTMLResponse)
async def remove_agent(request: Request, agent_id: int):
    agent = await get_notification_agent(agent_id)
    name = agent["name"] if agent else str(agent_id)
    await delete_notification_agent(agent_id)
    await log_audit("Notification agent deleted", name, request.client.host)
    return RedirectResponse("/settings#notifications", status_code=303)


def _form_to_agent(form) -> dict:
    agent_type = form.get("agent_type", "webhook")
    name = form.get("name", AGENT_TYPES.get(agent_type, {}).get("label", "Agent"))
    events = [e for e in ("condemned", "reminder", "deleted", "clean_scan") if form.get(f"event_{e}")]

    reminder_days = form.get("reminder_days", "").strip()

    # Build config dict based on agent type
    if agent_type == "discord":
        config = {
            "webhook_url": form.get("webhook_url", ""),
            "mention": form.get("mention", ""),
            "avatar_url": form.get("avatar_url", ""),
            "reminder_days": reminder_days,
        }
    elif agent_type == "pushover":
        config = {
            "user_key": form.get("user_key", ""),
            "api_token": form.get("api_token", ""),
            "priority": form.get("priority", "0"),
            "device": form.get("device", ""),
            "reminder_days": reminder_days,
        }
    elif agent_type == "ntfy":
        config = {
            "server_url": form.get("server_url", "https://ntfy.sh"),
            "topic": form.get("topic", ""),
            "token": form.get("token", ""),
            "priority": form.get("priority", "default"),
            "reminder_days": reminder_days,
        }
    elif agent_type == "apprise":
        config = {
            "server_url": form.get("server_url", ""),
            "tags": form.get("tags", ""),
            "reminder_days": reminder_days,
        }
    else:  # webhook
        config = {
            "url": form.get("url", ""),
            "method": form.get("method", "POST"),
            "headers": form.get("headers", ""),
            "reminder_days": reminder_days,
        }

    return {
        "name": name,
        "agent_type": agent_type,
        "enabled": 1,
        "config": json.dumps(config),
        "events": json.dumps(events),
    }


# ── Rules ─────────────────────────────────────────────────────────────────────

@router.get("/rules", response_class=HTMLResponse)
async def rules_page(request: Request):
    rules = await get_rules()
    settings = await get_all_settings()
    return templates.TemplateResponse("rules.html", {
        "request": request,
        "rules": rules,
        "settings": settings,
    })


@router.post("/rules/new", response_class=HTMLResponse)
async def new_rule(request: Request):
    return templates.TemplateResponse("rule_form.html", {
        "request": request,
        "rule": {},
        "action": "/rules/create",
    })


@router.post("/rules/create")
async def create_rule(request: Request):
    form = await request.form()
    rule = _form_to_rule(form)
    await upsert_rule(rule)
    await log_audit("Rule created", rule["name"], request.client.host)
    return RedirectResponse("/rules", status_code=303)


@router.get("/rules/{rule_id}/edit", response_class=HTMLResponse)
async def edit_rule(request: Request, rule_id: int):
    rule = await get_rule(rule_id)
    for genre_field in ("exclude_genres", "include_genres"):
        if rule and rule.get(genre_field):
            try:
                rule[genre_field] = ", ".join(json.loads(rule[genre_field]))
            except Exception:
                pass
    settings = await get_all_settings()
    return templates.TemplateResponse("rule_page.html", {
        "request": request,
        "rule": rule or {},
        "action": f"/rules/{rule_id}/update",
        "settings": settings,
    })


@router.post("/rules/{rule_id}/update")
async def update_rule(request: Request, rule_id: int):
    form = await request.form()
    rule = _form_to_rule(form)
    rule["id"] = rule_id
    await upsert_rule(rule)
    await log_audit("Rule updated", rule["name"], request.client.host)
    return RedirectResponse("/rules", status_code=303)


@router.post("/rules/{rule_id}/duplicate")
async def duplicate_rule(request: Request, rule_id: int):
    rule = await get_rule(rule_id)
    if rule:
        copy = {k: v for k, v in rule.items() if k != "id"}
        copy["name"] = f"{copy['name']} (copy)"
        new_id = await upsert_rule(copy)
        await log_audit("Rule duplicated", copy["name"], request.client.host)
        return RedirectResponse(f"/rules/{new_id}/edit", status_code=303)
    return RedirectResponse("/rules", status_code=303)


@router.post("/rules/{rule_id}/toggle", response_class=HTMLResponse)
async def toggle_rule(request: Request, rule_id: int):
    rule = await get_rule(rule_id)
    if rule:
        rule["enabled"] = 0 if rule["enabled"] else 1
        await upsert_rule(rule)
        state = "enabled" if rule["enabled"] else "disabled"
        await log_audit(f"Rule {state}", rule["name"], request.client.host)
    return RedirectResponse("/rules", status_code=303)


@router.post("/rules/{rule_id}/delete")
async def remove_rule(request: Request, rule_id: int):
    rule = await get_rule(rule_id)
    name = rule["name"] if rule else str(rule_id)
    await delete_rule(rule_id)
    await log_audit("Rule deleted", name, request.client.host)
    return RedirectResponse("/rules", status_code=303)


# ── Support ───────────────────────────────────────────────────────────────────

@router.get("/support", response_class=HTMLResponse)
async def support_redirect():
    return RedirectResponse("/support/guide", status_code=302)


@router.get("/support/audit", response_class=HTMLResponse)
async def support_audit(request: Request):
    settings = await get_all_settings()
    entries = await get_audit_log(limit=200)
    return templates.TemplateResponse("support_audit.html", {
        "request": request,
        "settings": settings,
        "entries": entries,
    })


@router.get("/support/logs", response_class=HTMLResponse)
async def support_logs(request: Request):
    settings = await get_all_settings()
    from ..log_buffer import memory_handler
    lines = list(memory_handler.lines)
    return templates.TemplateResponse("support_logs.html", {
        "request": request,
        "settings": settings,
        "lines": lines,
    })


@router.get("/support/logs/fragment", response_class=HTMLResponse)
async def support_logs_fragment():
    from ..log_buffer import memory_handler
    lines = list(memory_handler.lines)
    escaped = "\n".join(
        line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        for line in lines
    )
    return HTMLResponse(escaped)


@router.get("/support/guide", response_class=HTMLResponse)
async def support_guide(request: Request):
    settings = await get_all_settings()
    return templates.TemplateResponse("support_guide.html", {
        "request": request,
        "settings": settings,
    })


@router.get("/support/backup", response_class=HTMLResponse)
async def support_backup(request: Request):
    settings = await get_all_settings()
    return templates.TemplateResponse("support_backup.html", {
        "request": request,
        "settings": settings,
    })


@router.post("/support/backup/config")
async def backup_config_download():
    import json as _json
    data = await export_config()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Response(
        content=_json.dumps(data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="warden_config_{ts}.json"'},
    )


@router.get("/support/backup/full")
async def backup_full_download():
    import asyncio as _asyncio
    data = await _asyncio.get_event_loop().run_in_executor(None, _full_backup_sync)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="warden_full_{ts}.db"'},
    )


@router.post("/support/restore", response_class=HTMLResponse)
async def restore_config(request: Request, backup_file: UploadFile = File(...)):
    settings = await get_all_settings()

    def _err(msg):
        return templates.TemplateResponse("support_backup.html", {
            "request": request, "settings": settings, "restore_error": msg,
        })

    try:
        content = await backup_file.read()
        data = json.loads(content)
    except Exception:
        return _err("Could not parse file — make sure it's a Warden config JSON backup.")

    if data.get("type") != "warden_config" or data.get("version") != 1:
        return _err("Invalid backup format. Only Warden config JSON backups (.json) can be restored here.")

    try:
        await import_config(data)
    except Exception as e:
        log.exception("Config restore failed")
        return _err(f"Restore failed: {e}")

    await log_audit("Config restored from backup", backup_file.filename or "", request.client.host)
    settings = await get_all_settings()
    return templates.TemplateResponse("support_backup.html", {
        "request": request,
        "settings": settings,
        "restore_success": "Configuration restored successfully. Settings, rules, and notification agents have been replaced.",
    })


@router.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request):
    return await _profile_response(request)


@router.post("/profile/username", response_class=HTMLResponse)
async def change_username(request: Request, username: str = Form(...)):
    if not username.strip():
        return await _profile_response(request, username_error="Username cannot be empty.")
    await set_auth_username(username.strip())
    request.session["username"] = username.strip()
    await log_audit("Username changed", "", request.client.host)
    return await _profile_response(request, username_success="Username updated.")


@router.post("/profile/password", response_class=HTMLResponse)
async def change_password_profile(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
):
    pw_hash = await get_auth_password_hash()
    if not verify_password(current_password, pw_hash or ""):
        return await _profile_response(request, pw_error="Current password is incorrect.")
    if len(new_password) < 8:
        return await _profile_response(request, pw_error="New password must be at least 8 characters.")
    if new_password != confirm_password:
        return await _profile_response(request, pw_error="New passwords do not match.")
    await set_auth_password_hash(hash_password(new_password))
    await log_audit("Password changed", "", request.client.host)
    return await _profile_response(request, pw_success="Password updated successfully.")


async def _profile_response(request: Request, **kwargs):
    settings = await get_all_settings()
    username = await get_auth_username()
    totp_enabled = await is_totp_enabled()
    passkeys = await get_passkeys()
    return templates.TemplateResponse("profile.html", {
        "request": request,
        "settings": settings,
        "username": username,
        "totp_enabled": totp_enabled,
        "passkeys": passkeys,
        **kwargs,
    })


@router.get("/profile/totp/setup", response_class=HTMLResponse)
async def totp_setup_get(request: Request):
    secret = request.session.get("pending_totp_secret")
    if not secret:
        return RedirectResponse("/profile", status_code=302)
    settings = await get_all_settings()
    return templates.TemplateResponse("totp_setup.html", {
        "request": request,
        "totp_uri": get_totp_uri(secret),
        "secret": secret,
        "settings": settings,
        "error": None,
    })


@router.post("/profile/totp/start-setup", response_class=HTMLResponse)
async def totp_start_setup(request: Request):
    secret = generate_totp_secret()
    request.session["pending_totp_secret"] = secret
    return RedirectResponse("/profile/totp/setup", status_code=302)


@router.post("/profile/totp/confirm", response_class=HTMLResponse)
async def totp_confirm(request: Request, code: str = Form(...)):
    secret = request.session.get("pending_totp_secret")
    settings = await get_all_settings()
    if not secret:
        return RedirectResponse("/profile", status_code=302)
    if not verify_totp(secret, code):
        return templates.TemplateResponse("totp_setup.html", {
            "request": request,
            "totp_uri": get_totp_uri(secret),
            "secret": secret,
            "settings": settings,
            "error": "Invalid code — please try again.",
        })
    plain_codes = generate_backup_codes()
    hashes = [hash_backup_code(c) for c in plain_codes]
    await enable_totp(secret, hashes)
    request.session.pop("pending_totp_secret", None)
    await log_audit("TOTP enabled", "", request.client.host)
    return templates.TemplateResponse("totp_backup_codes.html", {
        "request": request,
        "backup_codes": plain_codes,
        "settings": settings,
    })


@router.post("/profile/totp/disable", response_class=HTMLResponse)
async def totp_disable(request: Request, password: str = Form(...), code: str = Form(...)):
    pw_hash = await get_auth_password_hash()
    if not verify_password(password, pw_hash or ""):
        return await _profile_response(request, totp_error="Incorrect password.")
    secret = await get_totp_secret()
    if not secret or not verify_totp(secret, code):
        return await _profile_response(request, totp_error="Invalid authenticator code.")
    await disable_totp()
    await log_audit("TOTP disabled", "", request.client.host)
    return await _profile_response(request, totp_success="Two-factor authentication disabled.")


# ── Passkey registration (protected) ──────────────────────────────────────────

@router.get("/profile/passkey/register/begin")
async def passkey_register_begin(request: Request):
    rp_id = (await get_setting("webauthn_rp_id") or "").strip()
    if not rp_id:
        return JSONResponse(
            {"error": "Configure Passkey Domain in Settings → General before adding a passkey."},
            status_code=400,
        )
    username = await get_auth_username()
    existing = await get_passkeys()
    options, challenge = _wh.generate_registration_options(
        rp_id=rp_id,
        rp_name="Warden",
        user_id=b"warden-admin",
        user_name=username,
        user_display_name=username,
        exclude_credentials=existing,
    )
    request.session["passkey_reg_challenge"] = _b64url_encode(challenge)
    return JSONResponse(options)


@router.post("/profile/passkey/register/complete")
async def passkey_register_complete(request: Request):
    challenge_b64 = request.session.pop("passkey_reg_challenge", None)
    if not challenge_b64:
        return JSONResponse({"error": "Session expired."}, status_code=400)
    rp_id = (await get_setting("webauthn_rp_id") or "").strip()
    if not rp_id:
        return JSONResponse({"error": "Passkeys not configured."}, status_code=400)
    try:
        body = await request.json()
        name = (body.get("name") or "").strip() or "Passkey"
        cred_data = body["credential"]
        verification = _wh.verify_registration_response(
            credential=cred_data,
            expected_challenge=_b64url_decode(challenge_b64),
            expected_rp_id=rp_id,
            expected_origin=f"https://{rp_id}",
        )
        passkey_id = await add_passkey(
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            name=name,
        )
        await log_audit(f"Passkey registered: {name}", ip=request.client.host)
        return JSONResponse({"ok": True, "id": passkey_id, "name": name})
    except Exception as e:
        log.warning("Passkey registration failed: %s", e)
        return JSONResponse({"error": str(e)}, status_code=400)


@router.post("/profile/passkey/delete/{passkey_id}", response_class=HTMLResponse)
async def passkey_delete(request: Request, passkey_id: int):
    await delete_passkey(passkey_id)
    await log_audit(f"Passkey deleted (id={passkey_id})", ip=request.client.host)
    return await _profile_response(request, passkey_success="Passkey removed.")


def _form_to_rule(form) -> dict:
    def opt_int(key): return int(form[key]) if form.get(key) else None
    def opt_float(key): return float(form[key]) if form.get(key) else None

    def genres_json(key):
        raw = form.get(key, "").strip()
        if not raw:
            return None
        lst = [g.strip() for g in raw.split(",") if g.strip()]
        return json.dumps(lst) if lst else None

    return {
        "name": form.get("name", "Unnamed Rule"),
        "media_type": form.get("media_type", "both"),
        "enabled": 1,
        "added_months": opt_int("added_months"),
        "unwatched_months": opt_int("unwatched_months"),
        "max_rating": opt_float("max_rating"),
        "min_rating": opt_float("min_rating"),
        "max_plays": opt_int("max_plays"),
        "min_size_gb": opt_float("min_size_gb"),
        "exclude_genres": genres_json("exclude_genres"),
        "include_genres": genres_json("include_genres"),
        "sort_order": opt_int("sort_order") or 0,
    }
