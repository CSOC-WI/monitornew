#!/usr/bin/env python3
"""
Background scheduler for SecNews Monitor.
Fetches all enabled feeds daily at a configured time (default 09:00 Asia/Bangkok)
and sends Discord / Telegram notifications if new articles are found.
"""

import logging
import threading
from datetime import datetime, timezone
from typing import Callable

import pytz
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

log = logging.getLogger("secnews.scheduler")

_scheduler: BackgroundScheduler | None = None
_get_db: Callable | None = None

JOB_ID   = "daily_fetch"
RUNS_COL = "scheduler_runs"   # MongoDB collection for run history


# ─── Job ──────────────────────────────────────────────────────────────────────

def _run_fetch_job():
    """Called by APScheduler in a background thread."""
    from security_news import fetch_feed, save_articles, init_collections
    from notifier import notify_new_articles

    db = _get_db()
    started = datetime.now(timezone.utc)
    log.info("Scheduled fetch started at %s", started.isoformat())

    total_new     = 0
    all_new_arts  = []
    sources_done  = 0
    errors        = []

    try:
        feeds = list(db.feeds.find({"enabled": True}, {"name": 1, "url": 1}))
        for feed in feeds:
            try:
                arts     = fetch_feed(feed["name"], feed["url"])
                cnt, new = save_articles(db, arts)
                db.feeds.update_one(
                    {"_id": feed["_id"]},
                    {"$set": {"last_fetch": datetime.now(timezone.utc)}}
                )
                total_new    += cnt
                all_new_arts += new
                sources_done += 1
            except Exception as e:
                errors.append(f"{feed['name']}: {e}")
                log.warning("Feed error %s: %s", feed["name"], e)

        log.info("Scheduled fetch done — %d new articles from %d sources",
                 total_new, sources_done)

        # Notify
        notify_results = {}
        if all_new_arts:
            notify_results = notify_new_articles(db, all_new_arts)

        # Persist run record
        db[RUNS_COL].insert_one({
            "ran_at":          started,
            "finished_at":     datetime.now(timezone.utc),
            "total_new":       total_new,
            "sources_fetched": sources_done,
            "errors":          errors,
            "notified":        bool(all_new_arts),
            "notify_results":  notify_results,
        })

    except Exception as e:
        log.error("Scheduled fetch fatal error: %s", e)
        try:
            db[RUNS_COL].insert_one({
                "ran_at":      started,
                "finished_at": datetime.now(timezone.utc),
                "error":       str(e),
            })
        except Exception:
            pass


# ─── Public API ───────────────────────────────────────────────────────────────

def start_scheduler(get_db: Callable,
                    hour:     int  = 9,
                    minute:   int  = 0,
                    tz_str:   str  = "Asia/Bangkok",
                    enabled:  bool = True) -> BackgroundScheduler:
    """
    Start (or restart) the background scheduler.
    Call this once from web.py main() after the DB is ready.
    """
    global _scheduler, _get_db
    _get_db = get_db

    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)

    tz = pytz.timezone(tz_str)
    _scheduler = BackgroundScheduler(timezone=tz)

    if enabled:
        _scheduler.add_job(
            _run_fetch_job,
            CronTrigger(hour=hour, minute=minute, timezone=tz),
            id=JOB_ID,
            name=f"Daily fetch {hour:02d}:{minute:02d} {tz_str}",
            replace_existing=True,
            misfire_grace_time=300,   # 5-minute window if server was down
        )

    _scheduler.start()
    log.info("Scheduler started — daily fetch at %02d:%02d %s (enabled=%s)",
             hour, minute, tz_str, enabled)
    return _scheduler


def reconfigure(hour: int, minute: int, tz_str: str, enabled: bool):
    """Hot-reload the cron trigger after settings change."""
    global _scheduler
    if _scheduler is None:
        return

    _scheduler.remove_all_jobs()
    if enabled:
        tz = pytz.timezone(tz_str)
        _scheduler.add_job(
            _run_fetch_job,
            CronTrigger(hour=hour, minute=minute, timezone=tz),
            id=JOB_ID,
            name=f"Daily fetch {hour:02d}:{minute:02d} {tz_str}",
            replace_existing=True,
            misfire_grace_time=300,
        )
        log.info("Scheduler reconfigured: %02d:%02d %s", hour, minute, tz_str)
    else:
        log.info("Scheduler disabled")


def run_now():
    """Trigger the fetch job immediately (for manual testing)."""
    t = threading.Thread(target=_run_fetch_job, daemon=True)
    t.start()


def get_status(db) -> dict:
    """Return scheduler status + recent run history."""
    job       = _scheduler.get_job(JOB_ID) if _scheduler else None
    next_run  = None
    job_name  = None
    if job:
        nr = job.next_run_time
        if nr:
            # Convert to Bangkok time for display
            bkk   = pytz.timezone("Asia/Bangkok")
            nr_bkk = nr.astimezone(bkk)
            next_run = nr_bkk.strftime("%Y-%m-%d %H:%M:%S %Z")
        job_name = job.name

    runs = list(
        db[RUNS_COL]
        .find({}, {"_id": 0})
        .sort("ran_at", -1)
        .limit(10)
    )

    return {
        "running":    bool(_scheduler and _scheduler.running),
        "job_active": bool(job),
        "job_name":   job_name,
        "next_run":   next_run,
        "recent_runs": runs,
    }
