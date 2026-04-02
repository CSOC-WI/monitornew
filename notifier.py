#!/usr/bin/env python3
"""
Discord & Telegram notification sender for SecNews Monitor.
Config is stored in MongoDB 'settings' collection  (_id = "notifications").
"""

import json
import urllib.request
import urllib.error
import logging
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger("secnews.notifier")


# ─── Discord ──────────────────────────────────────────────────────────────────

def send_discord(webhook_url: str, articles: list[dict]) -> tuple[bool, str]:
    """POST new articles to a Discord webhook as a rich embed."""
    if not webhook_url:
        return False, "No webhook URL"
    if not articles:
        return False, "No articles"

    count = len(articles)
    lines = []
    for a in articles[:10]:
        title = (a.get("title") or "Untitled")[:90]
        src   = a.get("source", "")
        url   = a.get("url", "")
        lines.append(f"• **[{title}]({url})**  ·  {src}")
    if count > 10:
        lines.append(f"_…and {count - 10} more_")

    embed = {
        "title":       f"🛡️ {count} New Security Article{'s' if count != 1 else ''}",
        "description": "\n".join(lines),
        "color":       0x58A6FF,
        "footer":      {"text": "SecNews Monitor  •  secnews"},
        "timestamp":   datetime.now(timezone.utc).isoformat(),
    }
    payload = json.dumps({"embeds": [embed]}).encode()
    req = urllib.request.Request(
        webhook_url, data=payload,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return True, f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:300]
        return False, f"HTTP {e.code}: {body}"
    except Exception as e:
        return False, str(e)


def test_discord(webhook_url: str) -> tuple[bool, str]:
    """Send a ping message to verify the webhook works."""
    if not webhook_url:
        return False, "No webhook URL"
    payload = json.dumps({
        "embeds": [{
            "title":       "✅ SecNews Monitor — Test",
            "description": "Discord webhook connected successfully!",
            "color":       0x3FB950,
            "footer":      {"text": "SecNews Monitor"},
            "timestamp":   datetime.now(timezone.utc).isoformat(),
        }]
    }).encode()
    req = urllib.request.Request(
        webhook_url, data=payload,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return True, f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: {e.read().decode(errors='replace')[:200]}"
    except Exception as e:
        return False, str(e)


# ─── Telegram ─────────────────────────────────────────────────────────────────

def _tg_request(token: str, method: str, payload: dict) -> tuple[bool, str]:
    url  = f"https://api.telegram.org/bot{token}/{method}"
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            result = json.loads(r.read())
            if result.get("ok"):
                return True, "OK"
            return False, result.get("description", "Unknown error")
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:300]
        return False, f"HTTP {e.code}: {body}"
    except Exception as e:
        return False, str(e)


def _tg_escape(text: str) -> str:
    """Escape characters reserved in Telegram MarkdownV2."""
    for ch in r"_*[]()~`>#+-=|{}.!":
        text = text.replace(ch, f"\\{ch}")
    return text


def send_telegram(token: str, chat_id: str, articles: list[dict]) -> tuple[bool, str]:
    """Send new articles to Telegram using Markdown formatting."""
    if not token or not chat_id:
        return False, "Missing token or chat_id"
    if not articles:
        return False, "No articles"

    count = len(articles)
    lines = [f"🛡️ *{count} new security article{'s' if count != 1 else ''}*\n"]
    for a in articles[:10]:
        title = (a.get("title") or "Untitled")[:80]
        # Minimal escaping for basic Markdown (not V2)
        safe  = title.replace("[", "").replace("]", "").replace("*", "").replace("_", "")
        url   = a.get("url", "")
        src   = a.get("source", "")
        lines.append(f"• [{safe}]({url}) — {src}")
    if count > 10:
        lines.append(f"…and {count - 10} more")

    payload = {
        "chat_id":                  chat_id,
        "text":                     "\n".join(lines),
        "parse_mode":               "Markdown",
        "disable_web_page_preview": True,
    }
    return _tg_request(token, "sendMessage", payload)


def test_telegram(token: str, chat_id: str) -> tuple[bool, str]:
    """Send a test message to verify bot + chat_id work."""
    if not token or not chat_id:
        return False, "Missing token or chat_id"
    payload = {
        "chat_id":    chat_id,
        "text":       "✅ *SecNews Monitor — Test*\nTelegram bot connected successfully\\!",
        "parse_mode": "Markdown",
    }
    return _tg_request(token, "sendMessage", payload)


def get_telegram_updates(token: str) -> tuple[bool, str]:
    """
    Convenience: fetch recent updates so the user can find their chat_id.
    Returns (ok, json_string_of_chat_ids_found).
    """
    if not token:
        return False, "No token"
    url = f"https://api.telegram.org/bot{token}/getUpdates"
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            result = json.loads(r.read())
            if not result.get("ok"):
                return False, result.get("description", "error")
            chats = {}
            for upd in result.get("result", []):
                msg = upd.get("message") or upd.get("channel_post") or {}
                chat = msg.get("chat", {})
                cid  = chat.get("id")
                name = chat.get("title") or chat.get("username") or chat.get("first_name") or ""
                if cid:
                    chats[str(cid)] = name
            if chats:
                items = ", ".join(f"{v} ({k})" for k, v in chats.items())
                return True, f"Found: {items}"
            return True, "No chats found yet — send a message to your bot first"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: {e.read().decode(errors='replace')[:200]}"
    except Exception as e:
        return False, str(e)


# ─── Unified notify ───────────────────────────────────────────────────────────

def notify_new_articles(db, articles: list[dict]) -> dict:
    """
    Read settings from MongoDB and dispatch notifications.
    Returns dict with 'discord' and 'telegram' results.
    """
    if not articles:
        return {"discord": None, "telegram": None}

    doc      = db.settings.find_one({"_id": "notifications"}) or {}
    results  = {}
    now_str  = datetime.now(timezone.utc).isoformat()

    # Discord
    d_cfg = doc.get("discord", {})
    if d_cfg.get("enabled") and d_cfg.get("webhook_url"):
        ok, msg = send_discord(d_cfg["webhook_url"], articles)
        results["discord"] = {"ok": ok, "msg": msg}
        log.info("Discord notify: ok=%s msg=%s", ok, msg)
    else:
        results["discord"] = None

    # Telegram
    t_cfg = doc.get("telegram", {})
    if t_cfg.get("enabled") and t_cfg.get("token") and t_cfg.get("chat_id"):
        ok, msg = send_telegram(t_cfg["token"], t_cfg["chat_id"], articles)
        results["telegram"] = {"ok": ok, "msg": msg}
        log.info("Telegram notify: ok=%s msg=%s", ok, msg)
    else:
        results["telegram"] = None

    # Persist notification log
    try:
        db.notify_log.insert_one({
            "sent_at":  now_str,
            "count":    len(articles),
            "discord":  results.get("discord"),
            "telegram": results.get("telegram"),
        })
    except Exception as e:
        log.warning("Could not save notify log: %s", e)

    return results
