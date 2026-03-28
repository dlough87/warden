import asyncio
import logging
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone as _tz

import uvicorn
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, Response
from .session_middleware import SessionMiddleware

from .auth import SESSION_SECRET
from .database import init_db, get_setting
from .scanner import run_scan
from .web.routes import router, auth_router, NeedsSetup, NotAuthenticated
from .log_buffer import memory_handler as _mem_handler

_LOG_FMT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=_LOG_FMT, stream=sys.stdout)
_mem_handler.setFormatter(logging.Formatter(_LOG_FMT))
logging.getLogger().addHandler(_mem_handler)
log = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──
    await init_db()
    schedule = await get_setting("schedule") or "0 8 * * *"
    tz = await get_setting("timezone") or "UTC"
    scheduler.add_job(run_scan, CronTrigger.from_crontab(schedule, timezone=tz), id="scan")
    scheduler.start()
    log.info(f"Scheduler started: {schedule} ({tz})")
    asyncio.create_task(_catchup_scan_if_missed(schedule, tz))

    yield

    # ── Shutdown ──
    scheduler.shutdown(wait=False)


app = FastAPI(title="Warden", docs_url=None, redoc_url=None, lifespan=lifespan)

# SessionMiddleware must wrap the app so session data is available to all routes.
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, session_cookie="warden_session", https_only=False)

# Auth routes (login / logout / setup) — no authentication required.
app.include_router(auth_router)

# All other routes — protected by require_auth dependency.
app.include_router(router)


@app.exception_handler(NeedsSetup)
async def _needs_setup_handler(request: Request, exc: NeedsSetup):
    return RedirectResponse("/setup", status_code=302)


@app.exception_handler(NotAuthenticated)
async def _not_authenticated_handler(request: Request, exc: NotAuthenticated):
    # HTMX polling requests: instruct the client to do a full-page redirect.
    if request.headers.get("HX-Request"):
        return Response(status_code=204, headers={"HX-Redirect": "/login"})
    return RedirectResponse(f"/login?next={request.url.path}", status_code=302)

async def reschedule(cron_expr: str):
    """Called from settings route when schedule is changed."""
    tz = await get_setting("timezone") or "UTC"
    scheduler.remove_all_jobs()
    scheduler.add_job(run_scan, CronTrigger.from_crontab(cron_expr, timezone=tz), id="scan")
    log.info(f"Rescheduled scan: {cron_expr} ({tz})")



async def _catchup_scan_if_missed(schedule: str, tz: str):
    await asyncio.sleep(3)  # Let the server fully start first
    from .database import get_stats
    stats = await get_stats()
    last_completed = stats.get("last_run_completed")
    if not last_completed:
        log.info("No previous scan on record — skipping catchup.")
        return
    try:
        last_dt = datetime.fromisoformat(last_completed)
        if last_dt.tzinfo is None:
            last_dt = last_dt.replace(tzinfo=_tz.utc)
        # Find the next scheduled time after the last scan
        trigger = CronTrigger.from_crontab(schedule, timezone=tz)
        next_fire = trigger.get_next_fire_time(None, last_dt)
        if next_fire and next_fire < datetime.now(_tz.utc):
            log.info(f"Missed scheduled scan at {next_fire} — running catchup.")
            await run_scan()
        else:
            log.info("No missed scan — skipping startup scan.")
    except Exception:
        log.exception("Error checking for missed scan; skipping catchup.")



if __name__ == "__main__":
    import os
    port = int(os.environ.get("WARDEN_PORT", 8787))
    log.info(f"Starting Warden on port {port}")
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=port,
        log_level="info",
        access_log=False,
    )
