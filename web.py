#!/usr/bin/env python3
"""
Security News Web UI — MongoDB edition
Run: python3 web.py [--host 0.0.0.0] [--port 8080]
"""

import os
import json
import re
import base64
import hashlib
import hmac
import logging
import argparse
import threading
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from pymongo import MongoClient, DESCENDING
from pymongo.errors import DuplicateKeyError
from bson import ObjectId
from bson.errors import InvalidId
from datetime import datetime

from security_news import (
    fetch_feed, save_articles, init_collections,
    fetch_url, parse_rss, DEFAULT_FEEDS,
)
from notifier  import (
    notify_new_articles, test_discord, test_telegram,
    send_discord, send_telegram, get_telegram_updates,
)
import scheduler as sched

log = logging.getLogger("secnews.web")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

# ─── Config ───────────────────────────────────────────────────────────────────

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
DB_NAME   = os.environ.get("MONGO_DB",  "secnews")

# Auth & Session — set ADMIN_USER / ADMIN_PASS env vars to enable
# If both are empty the server still runs but warns (suitable for localhost-only)
_ADMIN_USER = os.environ.get("ADMIN_USER", "").strip()
_ADMIN_PASS = os.environ.get("ADMIN_PASS", "").strip()
_AUTH_ENABLED = bool(_ADMIN_USER and _ADMIN_PASS)

_SESSION_SECRET = os.environ.get("SESSION_SECRET", os.urandom(32).hex())

# ─── Rate limiter (in-memory, per IP, resets every 60 s) ─────────────────────
_RATE_LOCK    = threading.Lock()
_RATE_STORE: dict = defaultdict(lambda: {"count": 0, "ts": 0.0})
_RATE_LIMIT   = int(os.environ.get("RATE_LIMIT", "120"))   # requests per minute
_RATE_WINDOW  = 60  # seconds

def _check_rate(ip: str) -> bool:
    """Return True if request is allowed, False if rate-limited."""
    import time
    now = time.monotonic()
    with _RATE_LOCK:
        rec = _RATE_STORE[ip]
        if now - rec["ts"] > _RATE_WINDOW:
            rec["count"] = 0
            rec["ts"]    = now
        rec["count"] += 1
        return rec["count"] <= _RATE_LIMIT

# ─── Security headers ─────────────────────────────────────────────────────────
_SECURITY_HEADERS = {
    "X-Content-Type-Options":  "nosniff",
    "X-Frame-Options":         "DENY",
    "X-XSS-Protection":        "1; mode=block",
    "Referrer-Policy":         "strict-origin-when-cross-origin",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    ),
    "Cache-Control":           "no-store",
}

MAX_BODY_BYTES = 1 * 1024 * 1024  # 1 MB

_client = None

def get_db():
    global _client
    if _client is None:
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    return _client[DB_NAME]


def oid(s: str) -> ObjectId:
    """Convert string to ObjectId; raises ValueError on invalid format."""
    try:
        return ObjectId(s)
    except (InvalidId, Exception) as exc:
        raise ValueError(f"Invalid id") from exc

# ─── HTML ────────────────────────────────────────────────────────────────────

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Login - Security News Monitor</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:#0d1117; --surface:#161b22; --border:#30363d;
    --text:#c9d1d9; --accent:#58a6ff; --red:#f85149;
    --input-bg:#010409; --input-border:#21262d;
  }
  * { box-sizing:border-box; margin:0; padding:0; font-family:'Inter', sans-serif; }
  body { display:flex; align-items:center; justify-content:center; min-height:100vh; background:var(--bg); color:var(--text); }
  .login-card {
    background: var(--surface); padding: 40px; border-radius: 12px;
    border: 1px solid var(--border); width: 100%; max-width: 400px;
    box-shadow: 0 24px 48px rgba(0,0,0,0.5);
    position: relative; overflow: hidden;
  }
  .login-card::before {
    content: ""; position: absolute; top: 0; left: 0; width: 100%; height: 4px;
    background: linear-gradient(90deg, var(--accent), var(--red));
  }
  .header { text-align: center; margin-bottom: 30px; }
  .header svg { color: var(--red); margin-bottom: 10px; }
  .header h1 { font-size: 24px; font-weight: 600; color: #fff; margin-bottom: 5px; }
  .header p { font-size: 14px; color: #8b949e; }
  .form-group { margin-bottom: 20px; }
  .form-group label { display: block; font-size: 13px; font-weight: 500; margin-bottom: 8px; }
  .form-input {
    width: 100%; background: var(--input-bg); border: 1px solid var(--input-border);
    color: var(--text); padding: 12px; border-radius: 6px; font-size: 14px;
    transition: border-color 0.15s, box-shadow 0.15s;
  }
  .form-input:focus {
    outline: none; border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(88,166,255,0.1);
  }
  .btn {
    width: 100%; background: var(--accent); color: #0d1117;
    border: none; padding: 12px; border-radius: 6px; font-size: 14px;
    font-weight: 600; cursor: pointer; transition: background 0.15s;
    margin-top: 10px; display: flex; align-items: center; justify-content: center; gap: 8px;
  }
  .btn:hover { background: #79c0ff; }
  .btn:disabled { opacity: 0.7; cursor: not-allowed; }
  .error-block {
    display: none; background: rgba(248,81,73,0.1); border: 1px solid rgba(248,81,73,0.25);
    color: var(--red); padding: 12px; border-radius: 6px; font-size: 13px;
    margin-bottom: 20px;
  }
</style>
</head>
<body>
<div class="login-card">
  <div class="header">
    <svg width="40" height="40" viewBox="0 0 24 24" fill="currentColor"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>
    <h1>SecNews Monitor</h1>
    <p>Sign in to access your dashboard</p>
  </div>
  <div id="errorBox" class="error-block"></div>
  <form id="loginForm" onsubmit="handleLogin(event)">
    <div class="form-group">
      <label>Username</label>
      <input type="text" id="username" class="form-input" required autofocus>
    </div>
    <div class="form-group">
      <label>Password</label>
      <input type="password" id="password" class="form-input" required>
    </div>
    <button type="submit" id="submitBtn" class="btn">Sign in</button>
  </form>
</div>
<script>
async function handleLogin(e) {
  e.preventDefault();
  const u = document.getElementById('username').value;
  const p = document.getElementById('password').value;
  const btn = document.getElementById('submitBtn');
  const err = document.getElementById('errorBox');
  
  btn.disabled = true;
  btn.textContent = 'Verifying...';
  err.style.display = 'none';
  
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({username: u, password: p})
    });
    const data = await res.json();
    if(res.ok && data.ok) {
      btn.textContent = 'Success!';
      window.location.href = '/';
    } else {
      throw new Error(data.error || 'Invalid credentials');
    }
  } catch(ex) {
    err.textContent = ex.message;
    err.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Sign in';
  }
}
</script>
</body>
</html>"""

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security News Monitor</title>
<style>
  :root {
    --bg:#0d1117; --surface:#161b22; --surface2:#1c2128; --border:#30363d;
    --accent:#58a6ff; --green:#3fb950; --red:#f85149; --orange:#d29922;
    --text:#c9d1d9; --muted:#8b949e; --radius:8px;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:14px}

  .layout{display:flex;min-height:100vh}
  .sidebar{width:240px;min-width:240px;background:var(--surface);border-right:1px solid var(--border);padding:20px 0;position:sticky;top:0;height:100vh;overflow-y:auto;display:flex;flex-direction:column}
  .main{flex:1;padding:24px;max-width:980px}

  .s-header{padding:0 16px 16px;border-bottom:1px solid var(--border);margin-bottom:12px}
  .s-header h1{font-size:15px;font-weight:600;display:flex;align-items:center;gap:7px}
  .s-header h1 svg{color:var(--red)}
  .s-header small{font-size:11px;color:var(--muted);margin-top:2px;display:block}

  .nav{padding:0 10px;margin-bottom:12px}
  .nav-item{display:flex;align-items:center;gap:9px;padding:8px 10px;border-radius:6px;cursor:pointer;color:var(--muted);font-size:13px;font-weight:500;transition:all .15s;text-decoration:none}
  .nav-item:hover{background:var(--surface2);color:var(--text)}
  .nav-item.active{background:var(--surface2);color:var(--accent)}
  .nav-item svg{flex-shrink:0}

  .stat-cards{padding:0 10px 12px;display:grid;grid-template-columns:1fr 1fr;gap:6px}
  .stat-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:10px}
  .stat-card .val{font-size:19px;font-weight:700;color:var(--accent)}
  .stat-card .lbl{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}

  .s-section{padding:0 10px}
  .s-section h3{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin:8px 2px 5px}
  .source-list{list-style:none}
  .source-list li{padding:1px 0}
  .source-list a{color:var(--text);text-decoration:none;font-size:12px;display:flex;justify-content:space-between;align-items:center;padding:5px 8px;border-radius:5px;cursor:pointer;transition:background .15s}
  .source-list a:hover,.source-list a.active{background:var(--surface2);color:var(--accent)}
  .source-list .badge{font-size:10px;background:var(--border);color:var(--muted);border-radius:10px;padding:1px 7px}
  .source-list a.active .badge{background:var(--accent);color:#000}

  .s-footer{padding:10px;margin-top:auto}
  .btn{background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:var(--radius);padding:7px 14px;font-size:13px;cursor:pointer;white-space:nowrap;transition:background .15s,border-color .15s}
  .btn:hover{background:var(--surface2);border-color:var(--accent);color:var(--accent)}
  .btn:disabled{opacity:.4;cursor:default}
  .btn.primary{background:var(--accent);border-color:var(--accent);color:#000;font-weight:600}
  .btn.primary:hover{opacity:.85}
  .btn.danger{color:var(--red);border-color:var(--red)}
  .btn.danger:hover{background:rgba(248,81,73,.1)}
  .btn.sm{padding:4px 10px;font-size:12px}
  select.btn{padding-right:28px;appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%238b949e'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 10px center}

  .page-title{font-size:20px;font-weight:700;margin-bottom:4px}
  .page-sub{font-size:13px;color:var(--muted);margin-bottom:20px}

  .topbar{display:flex;gap:8px;margin-bottom:18px;flex-wrap:wrap;align-items:center}
  .search-wrap{flex:1;min-width:180px;position:relative}
  .search-wrap svg{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--muted);pointer-events:none}
  .search-input{width:100%;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:14px;padding:7px 12px 7px 33px;outline:none;transition:border .15s}
  .search-input:focus{border-color:var(--accent)}
  .search-input::placeholder{color:var(--muted)}

  .results-info{font-size:12px;color:var(--muted);margin-bottom:12px}
  .results-info span{color:var(--text);font-weight:500}

  .articles{display:flex;flex-direction:column;gap:10px}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;transition:border-color .15s}
  .card:hover{border-color:var(--accent)}
  .card-meta{display:flex;align-items:center;gap:8px;margin-bottom:7px;flex-wrap:wrap}
  .source-tag{font-size:11px;font-weight:600;padding:2px 8px;border-radius:12px;background:rgba(88,166,255,.12);color:var(--accent);border:1px solid rgba(88,166,255,.2)}
  .date-tag{font-size:11px;color:var(--muted)}
  .card-title{font-size:14px;font-weight:600;line-height:1.4;margin-bottom:5px}
  .card-title a{color:var(--text);text-decoration:none}
  .card-title a:hover{color:var(--accent)}
  .card-summary{font-size:12px;color:var(--muted);line-height:1.5}
  .src-krebs{background:rgba(248,81,73,.12);color:#f85149;border-color:rgba(248,81,73,.2)}
  .src-cisa,.src-cert{background:rgba(63,185,80,.12);color:#3fb950;border-color:rgba(63,185,80,.2)}
  .src-nvd{background:rgba(210,153,34,.12);color:#d29922;border-color:rgba(210,153,34,.2)}

  .pagination{display:flex;gap:5px;align-items:center;justify-content:center;margin-top:22px;flex-wrap:wrap}
  .page-btn{background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:5px 11px;font-size:13px;cursor:pointer;transition:all .15s}
  .page-btn:hover:not(:disabled){border-color:var(--accent);color:var(--accent)}
  .page-btn.active{background:var(--accent);border-color:var(--accent);color:#000;font-weight:600}
  .page-btn:disabled{opacity:.3;cursor:default}

  .loading{text-align:center;padding:48px;color:var(--muted)}
  .spinner{display:inline-block;width:22px;height:22px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite;margin-bottom:8px}
  @keyframes spin{to{transform:rotate(360deg)}}
  .empty{text-align:center;padding:48px;color:var(--muted)}

  /* ── Filter bar ── */
  .filter-bar{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap;align-items:flex-end;padding:12px 14px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius)}
  .filter-group{display:flex;flex-direction:column;gap:4px;flex-shrink:0}
  .filter-group label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}
  .date-input{background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:13px;padding:6px 9px;outline:none;width:138px;transition:border .15s;cursor:pointer}
  .date-input:focus{border-color:var(--accent)}
  .date-input::-webkit-calendar-picker-indicator{filter:invert(.55);cursor:pointer}
  .filter-sep{width:1px;background:var(--border);align-self:stretch;margin:0 2px;flex-shrink:0}
  .sp-wrap{position:relative}
  .sp-btn{display:flex;align-items:center;gap:6px;padding:6px 11px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:13px;cursor:pointer;white-space:nowrap;transition:border .15s;height:32px}
  .sp-btn:hover,.sp-btn.open{border-color:var(--accent);color:var(--accent)}
  .sp-btn.has-filter{border-color:var(--accent);color:var(--accent)}
  .sp-cnt{font-size:10px;background:var(--accent);color:#000;border-radius:10px;padding:1px 6px;font-weight:700;min-width:18px;text-align:center}
  .sp-menu{position:absolute;top:calc(100% + 5px);left:0;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);min-width:240px;max-height:300px;overflow-y:auto;z-index:60;box-shadow:0 8px 28px rgba(0,0,0,.5);display:none}
  .sp-menu.open{display:block;animation:fadeUp .15s ease}
  .sp-head{display:flex;justify-content:space-between;align-items:center;padding:8px 12px;border-bottom:1px solid var(--border);font-size:11px;position:sticky;top:0;background:var(--surface);z-index:1}
  .sp-head span{color:var(--muted)}
  .sp-head a{color:var(--accent);cursor:pointer}
  .sp-head a:hover{text-decoration:underline}
  .sp-item{display:flex;align-items:center;gap:9px;padding:7px 12px;cursor:pointer;transition:background .1s}
  .sp-item:hover{background:var(--surface2)}
  .sp-item input[type=checkbox]{accent-color:var(--accent);cursor:pointer;width:13px;height:13px;flex-shrink:0}
  .sp-item label{cursor:pointer;font-size:13px;flex:1}
  .sp-item-cnt{font-size:10px;color:var(--muted)}
  .filter-apply{margin-left:auto}

  /* ── Category filter chips ── */
  .cat-bar{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px;align-items:center}
  .cat-bar-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-right:2px;white-space:nowrap}
  .cat-chip{display:inline-flex;align-items:center;gap:5px;border-radius:20px;padding:4px 11px;font-size:12px;font-weight:500;cursor:pointer;border:1px solid var(--border);background:var(--surface2);color:var(--muted);transition:all .15s;user-select:none}
  .cat-chip:hover{border-color:var(--accent);color:var(--text)}
  .cat-chip.active{color:#000;font-weight:600}
  .cat-chip[data-cat="ransomware"].active{background:#f85149;border-color:#f85149}
  .cat-chip[data-cat="databreach"].active{background:#d29922;border-color:#d29922}
  .cat-chip[data-cat="vulnerability"].active{background:#388bfd;border-color:#388bfd}
  .cat-chip[data-cat="malware"].active{background:#bc8cff;border-color:#bc8cff}
  .cat-chip[data-cat="apt"].active{background:#ff7b72;border-color:#ff7b72}
  .cat-chip[data-cat="phishing"].active{background:#3fb950;border-color:#3fb950}
  .cat-chip[data-cat="other"].active{background:#8b949e;border-color:#8b949e;color:#fff}
  .cat-chip .cat-dot{width:7px;height:7px;border-radius:50%;background:currentColor;opacity:.7;flex-shrink:0}

  /* Active filter chips */
  .active-filters{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px;min-height:4px}
  .chip{display:inline-flex;align-items:center;gap:4px;border-radius:20px;padding:3px 8px 3px 10px;font-size:12px}
  .chip-src{background:rgba(88,166,255,.1);border:1px solid rgba(88,166,255,.25);color:var(--accent)}
  .chip-date{background:rgba(210,153,34,.1);border:1px solid rgba(210,153,34,.25);color:var(--orange)}
  .chip-cat{background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.25);color:var(--red)}
  .chip-x{cursor:pointer;opacity:.55;font-size:15px;line-height:1;margin-left:1px}
  .chip-x:hover{opacity:1}

  /* Sources page */
  .feeds-toolbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;gap:10px;flex-wrap:wrap}
  .add-feed-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px;margin-bottom:20px}
  .add-feed-card h3{font-size:13px;font-weight:600;margin-bottom:14px}
  .form-row{display:flex;gap:10px;flex-wrap:wrap}
  .form-group{display:flex;flex-direction:column;gap:5px;flex:1;min-width:160px}
  .form-group label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px}
  .form-input{background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:13px;padding:7px 10px;outline:none;transition:border .15s;width:100%}
  .form-input:focus{border-color:var(--accent)}
  .form-input::placeholder{color:var(--muted)}
  .form-actions{display:flex;align-items:flex-end;gap:8px;flex-shrink:0}
  .test-result{font-size:12px;margin-top:8px;padding:6px 10px;border-radius:5px;display:none}
  .test-result.ok{background:rgba(63,185,80,.1);color:var(--green);border:1px solid rgba(63,185,80,.2)}
  .test-result.err{background:rgba(248,81,73,.1);color:var(--red);border:1px solid rgba(248,81,73,.2)}

  .feed-table{width:100%;border-collapse:collapse}
  .feed-table th{text-align:left;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;padding:8px 12px;border-bottom:1px solid var(--border)}
  .feed-table td{padding:10px 12px;border-bottom:1px solid var(--border);font-size:13px;vertical-align:middle}
  .feed-table tr:last-child td{border-bottom:none}
  .feed-table tr:hover td{background:var(--surface2)}
  .feed-name{font-weight:500}
  .feed-url{color:var(--muted);font-size:12px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .feed-url a{color:var(--muted);text-decoration:none}
  .feed-url a:hover{color:var(--accent)}
  .feed-actions{display:flex;gap:6px;align-items:center}
  .toggle{position:relative;display:inline-block;width:34px;height:18px;cursor:pointer}
  .toggle input{opacity:0;width:0;height:0}
  .toggle-slider{position:absolute;inset:0;background:var(--border);border-radius:18px;transition:.2s}
  .toggle-slider:before{content:'';position:absolute;width:13px;height:13px;left:2.5px;bottom:2.5px;background:#fff;border-radius:50%;transition:.2s}
  .toggle input:checked+.toggle-slider{background:var(--green)}
  .toggle input:checked+.toggle-slider:before{transform:translateX(16px)}
  .count-badge{font-size:11px;background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:2px 8px;color:var(--muted)}

  .toast{position:fixed;bottom:22px;right:22px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:11px 16px;font-size:13px;z-index:999;display:none;box-shadow:0 4px 20px rgba(0,0,0,.4)}
  .toast.show{display:block;animation:fadeUp .2s ease}
  .toast.success{border-color:var(--green);color:var(--green)}
  .toast.error{border-color:var(--red);color:var(--red)}
  @keyframes fadeUp{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}

  .fetch-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;display:none;align-items:center;justify-content:center}
  .fetch-overlay.show{display:flex}
  .fetch-box{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:28px 32px;text-align:center;min-width:260px}
  .fetch-box h3{margin-bottom:6px}
  .fetch-box p{color:var(--muted);font-size:13px}
  .fetch-bar{margin-top:14px;background:var(--border);border-radius:4px;height:4px;overflow:hidden}
  .fetch-bar-inner{height:100%;background:var(--accent);border-radius:4px;animation:prog 3s ease-in-out infinite}
  @keyframes prog{0%{width:5%}50%{width:80%}100%{width:95%}}

  .modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:200;display:none;align-items:center;justify-content:center}
  .modal-overlay.show{display:flex}
  .modal{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px;min-width:300px;max-width:440px}
  .modal h3{font-size:15px;font-weight:600;margin-bottom:8px}
  .modal p{font-size:13px;color:var(--muted);margin-bottom:18px;line-height:1.5}
  .modal-actions{display:flex;gap:8px;justify-content:flex-end}

  /* ── Settings page ── */
  .settings-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px}
  @media(max-width:820px){.settings-grid{grid-template-columns:1fr}}
  .settings-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px}
  .settings-card h3{font-size:13px;font-weight:600;margin-bottom:4px;display:flex;align-items:center;gap:8px}
  .settings-card .sub{font-size:12px;color:var(--muted);margin-bottom:16px}
  .settings-card .form-group{margin-bottom:12px}
  .settings-card .form-group label{display:block;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px;margin-bottom:4px}
  .settings-card .form-input{background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:13px;padding:7px 10px;outline:none;transition:border .15s;width:100%}
  .settings-card .form-input:focus{border-color:var(--accent)}
  .settings-card .form-input::placeholder{color:var(--muted)}
  .card-actions{display:flex;align-items:center;gap:8px;margin-top:14px;flex-wrap:wrap}
  .status-dot{width:8px;height:8px;border-radius:50%;background:var(--border);flex-shrink:0}
  .status-dot.ok{background:var(--green)}
  .status-dot.err{background:var(--red)}
  .status-dot.idle{background:var(--orange)}
  .status-msg{font-size:12px;color:var(--muted)}
  .toggle-row{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-top:1px solid var(--border);margin-top:12px}
  .toggle-row span{font-size:13px}
  .time-row{display:flex;gap:10px;align-items:flex-end}
  .time-row .form-group{flex:1}
  .sched-info{background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:10px 12px;font-size:12px;color:var(--muted);margin-top:12px}
  .sched-info .sched-next{color:var(--green);font-weight:600}

  .runs-table{width:100%;border-collapse:collapse;margin-top:16px}
  .runs-table th{text-align:left;font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;padding:6px 10px;border-bottom:1px solid var(--border)}
  .runs-table td{padding:8px 10px;border-bottom:1px solid var(--border);font-size:12px;vertical-align:top}
  .runs-table tr:last-child td{border-bottom:none}
  .pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px}
  .pill.new{background:rgba(63,185,80,.15);color:var(--green)}
  .pill.none{background:var(--surface2);color:var(--muted)}
  .pill.sent{background:rgba(88,166,255,.15);color:var(--accent)}
  .pill.fail{background:rgba(248,81,73,.15);color:var(--red)}

  .notify-hint{font-size:11px;color:var(--muted);display:flex;align-items:center;gap:5px;margin-top:6px}
  .notify-hint code{background:var(--surface2);border:1px solid var(--border);border-radius:3px;padding:1px 5px;font-size:10px}

  @media(max-width:680px){
    .layout{flex-direction:column}
    .sidebar{width:100%;height:auto;position:static}
    .main{padding:14px}
    .feed-url{max-width:160px}
  }
</style>
</head>
<body>
<div class="layout">

<aside class="sidebar">
  <div class="s-header">
    <h1>
      <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>
      SecNews Monitor
    </h1>
    <small>Global Cybersecurity Feed</small>
  </div>

  <nav class="nav">
    <a class="nav-item active" id="navNews" onclick="showPage('news')">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 6h16M4 12h16M4 18h12"/></svg>
      News Feed
    </a>
    <a class="nav-item" id="navSources" onclick="showPage('sources')">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 4.93a10 10 0 0 0 0 14.14"/></svg>
      Manage Sources
    </a>
    <a class="nav-item" id="navSettings" onclick="showPage('settings')">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
      Notifications
      <span id="navNotifyBadge" style="display:none;margin-left:auto;width:7px;height:7px;border-radius:50%;background:var(--green)"></span>
    </a>
  </nav>

  <div class="stat-cards">
    <div class="stat-card"><div class="val" id="statTotal">—</div><div class="lbl">Articles</div></div>
    <div class="stat-card"><div class="val" id="statFeeds">—</div><div class="lbl">Sources</div></div>
  </div>

  <div class="s-section" id="sidebarSourcesSection">
    <h3>Filter by Source</h3>
    <ul class="source-list" id="sourceList">
      <li><a class="active" onclick="filterSource(null,this)">
        <span>All Sources</span><span class="badge" id="badgeAll">0</span>
      </a></li>
    </ul>
  </div>

  <div class="s-footer" style="display:flex;flex-direction:column;gap:6px">
    <button class="btn" style="width:100%;font-size:12px;color:var(--text);background:var(--surface2)" onclick="logout()" title="Securely sign out">
      <svg style="vertical-align:-3px;margin-right:2px" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></svg>
      Sign Out
    </button>
    <button class="btn primary" style="width:100%" onclick="triggerFetchAll()">
      ⬇ Fetch All Feeds
    </button>
    <button class="btn" style="width:100%;font-size:12px" onclick="fixDates()" id="btnFixDates" title="Back-fill published_dt for existing articles">
      ⚙ Fix Article Dates
    </button>
  </div>
</aside>

<main class="main">

  <!-- NEWS PAGE -->
  <div id="pageNews">
    <!-- Top controls -->
    <div class="topbar">
      <div class="search-wrap">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <input id="searchInput" class="search-input" type="text" placeholder="Search title, summary…" oninput="onSearch()">
      </div>
      <select class="btn" id="sortSelect" onchange="reloadNews()">
        <option value="published">Newest First</option>
        <option value="fetched_at">Recently Fetched</option>
      </select>
      <select class="btn" id="perPageSelect" onchange="reloadNews()">
        <option value="25">25 / page</option>
        <option value="50" selected>50 / page</option>
        <option value="100">100 / page</option>
      </select>
    </div>

    <!-- Category chips -->
    <div class="cat-bar">
      <span class="cat-bar-label">🏷 Category:</span>
      <span class="cat-chip" data-cat="ransomware" onclick="toggleCategory('ransomware',this)"><span class="cat-dot"></span>Ransomware</span>
      <span class="cat-chip" data-cat="databreach" onclick="toggleCategory('databreach',this)"><span class="cat-dot"></span>Data Breach</span>
      <span class="cat-chip" data-cat="vulnerability" onclick="toggleCategory('vulnerability',this)"><span class="cat-dot"></span>Vulnerability</span>
      <span class="cat-chip" data-cat="malware" onclick="toggleCategory('malware',this)"><span class="cat-dot"></span>Malware</span>
      <span class="cat-chip" data-cat="apt" onclick="toggleCategory('apt',this)"><span class="cat-dot"></span>APT / Espionage</span>
      <span class="cat-chip" data-cat="phishing" onclick="toggleCategory('phishing',this)"><span class="cat-dot"></span>Phishing</span>
      <span class="cat-chip" data-cat="other" onclick="toggleCategory('other',this)"><span class="cat-dot"></span>Other</span>
    </div>

    <!-- Filter bar -->
    <div class="filter-bar">
      <div class="filter-group">
        <label>From</label>
        <input type="date" id="dateFrom" class="date-input" onchange="syncDateMin()">
      </div>
      <div class="filter-group">
        <label>To</label>
        <input type="date" id="dateTo" class="date-input" onchange="syncDateMax()">
      </div>

      <div class="filter-sep"></div>

      <!-- Multi-source dropdown -->
      <div class="filter-group">
        <label>Sources</label>
        <div class="sp-wrap">
          <button class="sp-btn" id="spBtn" onclick="toggleSourcePicker(event)">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
            <span id="spBtnLabel">All Sources</span>
            <span id="spBtnCnt" class="sp-cnt" style="display:none"></span>
            <span style="margin-left:2px;font-size:10px;opacity:.6">▾</span>
          </button>
          <div class="sp-menu" id="spMenu">
            <div class="sp-head">
              <span id="spHeadCount">0 sources</span>
              <div style="display:flex;gap:10px">
                <a onclick="checkAllSources()">All</a>
                <a onclick="uncheckAllSources()">None</a>
              </div>
            </div>
            <div id="spItems"></div>
          </div>
        </div>
      </div>

      <div class="filter-sep"></div>

      <div class="filter-group" style="justify-content:flex-end">
        <label>&nbsp;</label>
        <div style="display:flex;gap:6px">
          <button class="btn primary" style="height:32px" onclick="applyFilters()">Apply</button>
          <button class="btn" style="height:32px" onclick="clearFilters()">Clear</button>
        </div>
      </div>
    </div>

    <!-- Active filter chips -->
    <div class="active-filters" id="activeFilters"></div>

    <div class="results-info" id="resultsInfo"></div>
    <div class="articles" id="articles">
      <div class="loading"><div class="spinner"></div><br>Loading…</div>
    </div>
    <div class="pagination" id="pagination"></div>
  </div>

  <!-- SOURCES PAGE -->
  <div id="pageSources" style="display:none">
    <div class="page-title">Manage Sources</div>
    <div class="page-sub">Add, remove, or toggle RSS/Atom feed sources — stored in MongoDB</div>

    <div class="add-feed-card">
      <h3>+ Add New Feed</h3>
      <div class="form-row">
        <div class="form-group" style="flex:1.2">
          <label>Source Name</label>
          <input id="newName" class="form-input" type="text" placeholder="e.g. TechTalkThai Security">
        </div>
        <div class="form-group" style="flex:2">
          <label>RSS / Atom Feed URL</label>
          <input id="newUrl" class="form-input" type="url" placeholder="https://example.com/feed.xml">
        </div>
        <div class="form-actions">
          <button class="btn" onclick="testFeed()" id="btnTest">Test</button>
          <button class="btn primary" onclick="addFeed()" id="btnAdd">Add Feed</button>
        </div>
      </div>
      <div id="testResult" class="test-result"></div>
    </div>

    <div class="feeds-toolbar">
      <div style="font-size:13px;color:var(--muted)"><span id="feedCount">0</span> sources configured</div>
      <div style="display:flex;gap:8px">
        <button class="btn sm" onclick="bulkToggle(true)">Enable All</button>
        <button class="btn sm" onclick="bulkToggle(false)">Disable All</button>
      </div>
    </div>

    <div style="overflow-x:auto">
      <table class="feed-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Feed URL</th>
            <th>Articles</th>
            <th>Last Fetch</th>
            <th>Enabled</th>
            <th></th>
          </tr>
        </thead>
        <tbody id="feedTableBody">
          <tr><td colspan="6" class="loading"><div class="spinner"></div></td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- SETTINGS PAGE -->
  <div id="pageSettings" style="display:none">
    <div class="page-title">Notifications &amp; Scheduler</div>
    <div class="page-sub">ตั้งค่าแจ้งเตือน Discord / Telegram และกำหนดเวลา fetch อัตโนมัติ</div>

    <div class="settings-grid">

      <!-- Discord card -->
      <div class="settings-card">
        <h3>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" style="color:#5865F2"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03z"/></svg>
          Discord Webhook
        </h3>
        <div class="sub">วาง Webhook URL จาก Server Settings → Integrations → Webhooks</div>
        <div class="form-group">
          <label>Webhook URL</label>
          <input id="discordUrl" class="form-input" type="url" placeholder="https://discord.com/api/webhooks/…">
        </div>
        <div class="card-actions">
          <button class="btn sm" onclick="testDiscord()" id="btnTestDiscord">Test</button>
          <button class="btn sm primary" onclick="saveDiscord()" id="btnSaveDiscord">Save</button>
          <span class="status-dot" id="discordDot"></span>
          <span class="status-msg" id="discordMsg"></span>
        </div>
        <div class="toggle-row">
          <span>Enable Discord alerts</span>
          <label class="toggle">
            <input type="checkbox" id="discordEnabled" onchange="saveDiscord()">
            <span class="toggle-slider"></span>
          </label>
        </div>
        <div class="notify-hint">
          ⚙ ไปที่ Discord → Server → Edit Channel → Integrations → New Webhook
        </div>
      </div>

      <!-- Telegram card -->
      <div class="settings-card">
        <h3>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" style="color:#29B6F6"><path d="M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm5.894 8.221-1.97 9.28c-.145.658-.537.818-1.084.508l-3-2.21-1.447 1.394c-.16.16-.295.295-.605.295l.213-3.053 5.56-5.023c.242-.213-.054-.333-.373-.12l-6.871 4.326-2.962-.924c-.643-.204-.657-.643.136-.953l11.57-4.461c.537-.194 1.006.131.833.941z"/></svg>
          Telegram Bot
        </h3>
        <div class="sub">สร้าง Bot ผ่าน @BotFather แล้วนำ Token และ Chat ID มาใส่</div>
        <div class="form-group">
          <label>Bot Token</label>
          <input id="tgToken" class="form-input" type="text" placeholder="123456:ABC-DEF…">
        </div>
        <div class="form-group">
          <label>Chat ID
            <span style="font-size:10px;font-weight:400;text-transform:none;letter-spacing:0;margin-left:6px">
              <a href="#" onclick="findChatId(event)" style="color:var(--accent);text-decoration:none">🔍 Find my Chat ID</a>
            </span>
          </label>
          <input id="tgChatId" class="form-input" type="text" placeholder="-100123456789 or @channel">
        </div>
        <div class="card-actions">
          <button class="btn sm" onclick="testTelegram()" id="btnTestTg">Test</button>
          <button class="btn sm primary" onclick="saveTelegram()" id="btnSaveTg">Save</button>
          <span class="status-dot" id="tgDot"></span>
          <span class="status-msg" id="tgMsg"></span>
        </div>
        <div class="toggle-row">
          <span>Enable Telegram alerts</span>
          <label class="toggle">
            <input type="checkbox" id="tgEnabled" onchange="saveTelegram()">
            <span class="toggle-slider"></span>
          </label>
        </div>
        <div class="notify-hint">
          ⚙ สร้าง Bot: <code>/newbot</code> ใน @BotFather · ส่งข้อความ Bot แล้ว กด Find my Chat ID
        </div>
      </div>

    </div>

    <!-- Scheduler card (full width) -->
    <div class="settings-card" style="margin-bottom:24px">
      <h3>
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
        Auto Fetch Scheduler
      </h3>
      <div class="sub">ดึงข่าวอัตโนมัติทุกวัน · Timezone: Asia/Bangkok (UTC+7)</div>

      <div class="time-row">
        <div class="form-group">
          <label>Hour (0–23)</label>
          <input id="schedHour" class="form-input" type="number" min="0" max="23" value="9" style="width:90px">
        </div>
        <div class="form-group">
          <label>Minute (0–59)</label>
          <input id="schedMinute" class="form-input" type="number" min="0" max="59" value="0" style="width:90px">
        </div>
        <div style="padding-bottom:1px">
          <button class="btn primary" onclick="saveScheduler()">Apply</button>
          <button class="btn sm" style="margin-left:6px" onclick="runNow()">▶ Run Now</button>
        </div>
      </div>

      <div class="toggle-row">
        <span>Enable auto-fetch</span>
        <label class="toggle">
          <input type="checkbox" id="schedEnabled" checked onchange="saveScheduler()">
          <span class="toggle-slider"></span>
        </label>
      </div>

      <div class="sched-info" id="schedInfo">
        <div>Loading scheduler status…</div>
      </div>
    </div>

    <!-- Recent runs -->
    <div class="settings-card">
      <h3>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        Recent Scheduler Runs
      </h3>
      <div style="overflow-x:auto">
        <table class="runs-table">
          <thead>
            <tr>
              <th>Ran At (Bangkok)</th>
              <th>Sources</th>
              <th>New Articles</th>
              <th>Notified</th>
              <th>Discord</th>
              <th>Telegram</th>
            </tr>
          </thead>
          <tbody id="runsTableBody">
            <tr><td colspan="6" class="loading"><div class="spinner"></div></td></tr>
          </tbody>
        </table>
      </div>
    </div>

  </div>

</main>
</div>

<!-- Fetch overlay -->
<div class="fetch-overlay" id="fetchOverlay">
  <div class="fetch-box">
    <div class="spinner"></div>
    <h3>Fetching Feeds…</h3>
    <p id="fetchStatus">Connecting to sources</p>
    <div class="fetch-bar"><div class="fetch-bar-inner"></div></div>
  </div>
</div>

<!-- Confirm modal -->
<div class="modal-overlay" id="modalOverlay">
  <div class="modal">
    <h3 id="modalTitle">Confirm</h3>
    <p id="modalBody"></p>
    <div class="modal-actions">
      <button class="btn" onclick="closeModal()">Cancel</button>
      <button class="btn danger" id="modalConfirm">Delete</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const CATEGORY_LABELS = {
  ransomware:    'Ransomware',
  databreach:    'Data Breach',
  vulnerability: 'Vulnerability',
  malware:       'Malware',
  apt:           'APT / Espionage',
  phishing:      'Phishing',
  other:         'Other',
};

const ns = {
  source: null, search: '', page: 1, total: 0, timer: null,
  dateFrom: '', dateTo: '',
  selectedSources: new Set(),
  allSources: [],   // [{source, count}] populated from stats
  category: null,   // active category filter key
};

// close source picker when clicking outside
document.addEventListener('click', e => {
  const menu = document.getElementById('spMenu');
  const btn  = document.getElementById('spBtn');
  if (menu && !menu.contains(e.target) && !btn.contains(e.target)) {
    menu.classList.remove('open');
    btn.classList.remove('open');
  }
});

function showPage(name) {
  document.getElementById('pageNews').style.display     = name==='news'     ? '' : 'none';
  document.getElementById('pageSources').style.display  = name==='sources'  ? '' : 'none';
  document.getElementById('pageSettings').style.display = name==='settings' ? '' : 'none';
  document.getElementById('sidebarSourcesSection').style.display = name==='news' ? '' : 'none';
  document.getElementById('navNews').classList.toggle('active',     name==='news');
  document.getElementById('navSources').classList.toggle('active',  name==='sources');
  document.getElementById('navSettings').classList.toggle('active', name==='settings');
  if (name === 'sources')  loadFeedTable();
  if (name === 'settings') loadSettings();
}

async function init() {
  loadStats();
  loadArticles();
}

async function loadStats() {
  try {
    const d = await fetchJSON('/api/stats');
    document.getElementById('statTotal').textContent = d.total.toLocaleString();
    document.getElementById('statFeeds').textContent = d.feed_count;
    document.getElementById('badgeAll').textContent  = d.total.toLocaleString();

    // sidebar source list
    const ul = document.getElementById('sourceList');
    while (ul.children.length > 1) ul.removeChild(ul.lastChild);
    d.sources.forEach(s => {
      const li = document.createElement('li');
      li.innerHTML = `<a onclick="filterSource(${JSON.stringify(s.source)},this)">
        <span>${esc(s.source)}</span><span class="badge">${s.count.toLocaleString()}</span></a>`;
      ul.appendChild(li);
    });

    // populate source picker (keep existing selections)
    ns.allSources = d.sources;
    populateSourcePicker();
  } catch(e) { console.error(e); }
}

async function loadArticles() {
  const el = document.getElementById('articles');
  const perPage = +document.getElementById('perPageSelect').value;
  const sort    = document.getElementById('sortSelect').value;

  const params = { page: ns.page, per_page: perPage, sort };
  if (ns.search)   params.q         = ns.search;
  if (ns.dateFrom) params.date_from = ns.dateFrom;
  if (ns.dateTo)   params.date_to   = ns.dateTo;
  if (ns.category) params.category  = ns.category;
  if (ns.selectedSources.size > 0) {
    params.sources = Array.from(ns.selectedSources).join(',');
  } else if (ns.source) {
    params.source = ns.source;
  }

  el.innerHTML = '<div class="loading"><div class="spinner"></div><br>Loading…</div>';
  try {
    const d = await fetchJSON(`/api/articles?${new URLSearchParams(params)}`);
    ns.total = d.total;

    // results info
    let info = `<span>${d.total.toLocaleString()}</span> articles`;
    if (ns.search) info += ` matching "<strong>${esc(ns.search)}</strong>"`;
    if (ns.category) info += ` in <strong>${CATEGORY_LABELS[ns.category]||ns.category}</strong>`;
    if (ns.selectedSources.size > 0) info += ` from <strong>${ns.selectedSources.size} source${ns.selectedSources.size>1?'s':''}</strong>`;
    else if (ns.source) info += ` from <strong>${esc(ns.source)}</strong>`;
    if (ns.dateFrom || ns.dateTo) {
      info += ` · ${ns.dateFrom||'…'} → ${ns.dateTo||'…'}`;
    }
    document.getElementById('resultsInfo').innerHTML = info;

    el.innerHTML = d.articles.length ? d.articles.map(renderCard).join('') : '<div class="empty"><p>No articles found.</p></div>';
    renderPagination(d.total, perPage);
  } catch(e) {
    el.innerHTML = '<div class="empty"><p style="color:var(--red)">Failed to load.</p></div>';
  }
}

function renderCard(a) {
  const date = (a.published||'').substring(0,10) || 'Unknown';
  const cls  = srcClass(a.source);
  const sum  = a.summary ? `<div class="card-summary">${esc(a.summary.substring(0,240))}${a.summary.length>240?'…':''}</div>` : '';
  return `<div class="card">
    <div class="card-meta"><span class="source-tag ${cls}">${esc(a.source)}</span><span class="date-tag">${date}</span></div>
    <div class="card-title"><a href="${esc(a.url)}" target="_blank" rel="noopener">${esc(a.title)}</a></div>${sum}</div>`;
}
function srcClass(s) {
  s = s.toLowerCase();
  if (s.includes('krebs')) return 'src-krebs';
  if (s.includes('cisa')||s.includes('cert')) return 'src-cisa';
  if (s.includes('nvd')) return 'src-nvd';
  return '';
}
function renderPagination(total, perPage) {
  const pages = Math.ceil(total/perPage);
  const el = document.getElementById('pagination');
  if (pages<=1){el.innerHTML='';return}
  let h = `<button class="page-btn" onclick="goPage(${ns.page-1})" ${ns.page===1?'disabled':''}>← Prev</button>`;
  pageRange(ns.page,pages).forEach(p=>{
    h += p==='…' ? `<span style="color:var(--muted);padding:0 4px">…</span>`
      : `<button class="page-btn ${p===ns.page?'active':''}" onclick="goPage(${p})">${p}</button>`;
  });
  h += `<button class="page-btn" onclick="goPage(${ns.page+1})" ${ns.page===pages?'disabled':''}>Next →</button>`;
  el.innerHTML = h;
}
function pageRange(cur,total){
  if(total<=7) return Array.from({length:total},(_,i)=>i+1);
  if(cur<=4)       return [1,2,3,4,5,'…',total];
  if(cur>=total-3) return [1,'…',total-4,total-3,total-2,total-1,total];
  return [1,'…',cur-1,cur,cur+1,'…',total];
}
function filterSource(src, el) {
  // sidebar quick-filter: clears multi-select
  ns.source = src;
  ns.selectedSources.clear();
  ns.page = 1;
  document.querySelectorAll('.source-list a').forEach(a => a.classList.remove('active'));
  el.classList.add('active');
  updateSourceBtn();
  renderActiveFilters();
  loadArticles();
}
function onSearch() {
  clearTimeout(ns.timer);
  ns.timer = setTimeout(() => { ns.search = document.getElementById('searchInput').value.trim(); ns.page=1; loadArticles(); }, 300);
}
function goPage(p)    { ns.page=p; loadArticles(); window.scrollTo(0,0); }
function reloadNews() { ns.page=1; loadArticles(); }

// ── Filter bar ────────────────────────────────────────────────────────────────
function syncDateMin() {
  const v = document.getElementById('dateFrom').value;
  document.getElementById('dateTo').min = v || '';
}
function syncDateMax() {
  const v = document.getElementById('dateTo').value;
  document.getElementById('dateFrom').max = v || '';
}

function applyFilters() {
  ns.dateFrom         = document.getElementById('dateFrom').value;
  ns.dateTo           = document.getElementById('dateTo').value;
  // selectedSources already updated live via checkboxes
  // clear sidebar single-source when multi-select is active
  if (ns.selectedSources.size > 0) {
    ns.source = null;
    document.querySelectorAll('.source-list a').forEach(a => a.classList.remove('active'));
    document.querySelector('.source-list a')?.classList.add('active');
  }
  ns.page = 1;
  renderActiveFilters();
  loadArticles();
  // close picker
  document.getElementById('spMenu').classList.remove('open');
  document.getElementById('spBtn').classList.remove('open');
}

function clearFilters() {
  ns.dateFrom = ''; ns.dateTo = '';
  ns.selectedSources.clear();
  document.getElementById('dateFrom').value = '';
  document.getElementById('dateTo').value   = '';
  document.getElementById('dateFrom').max   = '';
  document.getElementById('dateTo').min     = '';
  // clear category
  ns.category = null;
  document.querySelectorAll('.cat-chip').forEach(c => c.classList.remove('active'));
  updateSourceBtn();
  renderActiveFilters();
  ns.page = 1;
  loadArticles();
}

// ── Category filter ───────────────────────────────────────────────────────────
function toggleCategory(cat, el) {
  if (ns.category === cat) {
    // deselect
    ns.category = null;
    el.classList.remove('active');
  } else {
    // deselect previous
    document.querySelectorAll('.cat-chip').forEach(c => c.classList.remove('active'));
    ns.category = cat;
    el.classList.add('active');
  }
  ns.page = 1;
  renderActiveFilters();
  loadArticles();
}

// ── Source picker ─────────────────────────────────────────────────────────────
function toggleSourcePicker(e) {
  e.stopPropagation();
  const menu = document.getElementById('spMenu');
  const btn  = document.getElementById('spBtn');
  const open = menu.classList.toggle('open');
  btn.classList.toggle('open', open);
}

function populateSourcePicker() {
  const container = document.getElementById('spItems');
  document.getElementById('spHeadCount').textContent = `${ns.allSources.length} sources`;
  container.innerHTML = ns.allSources.map(s => `
    <div class="sp-item" onclick="toggleSourceItem(event,'${esc(s.source)}')">
      <input type="checkbox" id="sp-${esc(s.source)}"
             ${ns.selectedSources.has(s.source) ? 'checked' : ''}
             onchange="toggleSourceItem(event,'${esc(s.source)}')">
      <label for="sp-${esc(s.source)}">${esc(s.source)}</label>
      <span class="sp-item-cnt">${s.count.toLocaleString()}</span>
    </div>`).join('');
  updateSourceBtn();
}

function toggleSourceItem(e, src) {
  e.stopPropagation();
  const cb = document.getElementById(`sp-${src}`);
  if (e.target !== cb) cb.checked = !cb.checked;
  if (cb.checked) ns.selectedSources.add(src);
  else            ns.selectedSources.delete(src);
  updateSourceBtn();
}

function checkAllSources()   { ns.allSources.forEach(s => { ns.selectedSources.add(s.source); document.getElementById(`sp-${s.source}`) && (document.getElementById(`sp-${s.source}`).checked=true); }); updateSourceBtn(); }
function uncheckAllSources() { ns.selectedSources.clear(); document.querySelectorAll('#spItems input').forEach(cb => cb.checked=false); updateSourceBtn(); }

function updateSourceBtn() {
  const cnt  = ns.selectedSources.size;
  const btn  = document.getElementById('spBtn');
  const lbl  = document.getElementById('spBtnLabel');
  const badge = document.getElementById('spBtnCnt');
  if (cnt === 0) {
    lbl.textContent = 'All Sources';
    badge.style.display = 'none';
    btn.classList.remove('has-filter');
  } else {
    lbl.textContent = cnt === 1 ? Array.from(ns.selectedSources)[0].substring(0,18) : `${cnt} selected`;
    badge.textContent = cnt;
    badge.style.display = '';
    btn.classList.add('has-filter');
  }
}

function renderActiveFilters() {
  const el = document.getElementById('activeFilters');
  let chips = '';
  if (ns.category) chips += `<span class="chip chip-cat">🏷 ${esc(CATEGORY_LABELS[ns.category]||ns.category)} <span class="chip-x" onclick="removeFilter('category')">×</span></span>`;
  if (ns.dateFrom) chips += `<span class="chip chip-date">From: ${ns.dateFrom} <span class="chip-x" onclick="removeFilter('dateFrom')">×</span></span>`;
  if (ns.dateTo)   chips += `<span class="chip chip-date">To: ${ns.dateTo} <span class="chip-x" onclick="removeFilter('dateTo')">×</span></span>`;
  ns.selectedSources.forEach(src => {
    chips += `<span class="chip chip-src">${esc(src)} <span class="chip-x" onclick="removeFilter('src','${esc(src)}')">×</span></span>`;
  });
  el.innerHTML = chips;
}

function removeFilter(type, val) {
  if (type === 'category') {
    ns.category = null;
    document.querySelectorAll('.cat-chip').forEach(c => c.classList.remove('active'));
  } else if (type === 'dateFrom') {
    ns.dateFrom = '';
    document.getElementById('dateFrom').value = '';
    document.getElementById('dateTo').min = '';
  } else if (type === 'dateTo') {
    ns.dateTo = '';
    document.getElementById('dateTo').value = '';
    document.getElementById('dateFrom').max = '';
  } else if (type === 'src') {
    ns.selectedSources.delete(val);
    const cb = document.getElementById(`sp-${val}`);
    if (cb) cb.checked = false;
    updateSourceBtn();
  }
  renderActiveFilters();
  ns.page = 1;
  loadArticles();
}

// ── Sources page ──────────────────────────────────────────────────────────────
async function loadFeedTable() {
  const tbody = document.getElementById('feedTableBody');
  tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:24px"><div class="spinner"></div></td></tr>';
  try {
    const feeds = await fetchJSON('/api/feeds');
    document.getElementById('feedCount').textContent = feeds.length;
    tbody.innerHTML = feeds.length ? feeds.map(f => `
      <tr id="feed-row-${f.id}">
        <td class="feed-name">${esc(f.name)}</td>
        <td class="feed-url"><a href="${esc(f.url)}" target="_blank" title="${esc(f.url)}">${esc(f.url)}</a></td>
        <td><span class="count-badge">${(f.article_count||0).toLocaleString()}</span></td>
        <td style="color:var(--muted);font-size:12px">${f.last_fetch ? f.last_fetch.substring(0,16).replace('T',' ') : '—'}</td>
        <td><label class="toggle">
          <input type="checkbox" ${f.enabled?'checked':''} onchange="toggleFeed('${f.id}',this.checked)">
          <span class="toggle-slider"></span>
        </label></td>
        <td><div class="feed-actions">
          <button class="btn sm" onclick="fetchOneFeed('${f.id}','${esc(f.name)}')" title="Fetch now">⬇</button>
          <button class="btn sm danger" onclick="confirmDelete('${f.id}','${esc(f.name)}')" title="Delete">✕</button>
        </div></td>
      </tr>`).join('')
      : '<tr><td colspan="6" class="empty">No feeds configured.</td></tr>';
  } catch(e) {
    tbody.innerHTML = '<tr><td colspan="6" style="color:var(--red);padding:16px">Failed to load feeds.</td></tr>';
  }
}

async function addFeed() {
  const name = document.getElementById('newName').value.trim();
  const url  = document.getElementById('newUrl').value.trim();
  if (!name || !url) { showToast('Name and URL are required', 'error'); return; }
  const btn = document.getElementById('btnAdd');
  btn.disabled = true;
  try {
    await postJSON('/api/feeds', {name, url});
    document.getElementById('newName').value = '';
    document.getElementById('newUrl').value  = '';
    document.getElementById('testResult').style.display = 'none';
    showToast(`Added "${name}"`, 'success');
    await loadFeedTable(); await loadStats();
  } catch(e) { showToast(e.message||'Failed', 'error'); }
  finally { btn.disabled = false; }
}

async function testFeed() {
  const url = document.getElementById('newUrl').value.trim();
  if (!url) { showToast('Enter a URL first', 'error'); return; }
  const btn = document.getElementById('btnTest');
  const res = document.getElementById('testResult');
  btn.disabled = true; btn.textContent = '…'; res.style.display = 'none';
  try {
    const d = await postJSON('/api/feeds/test', {url});
    res.className = 'test-result ok';
    res.textContent = `✓ Feed OK — found ${d.count} articles (sample: "${d.sample}")`;
  } catch(e) {
    res.className = 'test-result err';
    res.textContent = `✗ ${e.message||'Could not parse feed'}`;
  } finally { res.style.display='block'; btn.disabled=false; btn.textContent='Test'; }
}

async function toggleFeed(id, enabled) {
  try { await patchJSON(`/api/feeds/${id}`, {enabled}); }
  catch(e) { showToast('Failed to update', 'error'); }
}

async function fetchOneFeed(id, name) {
  const overlay = document.getElementById('fetchOverlay');
  document.getElementById('fetchStatus').textContent = `Fetching "${name}"…`;
  overlay.classList.add('show');
  try {
    const d = await postJSON(`/api/feeds/${id}/fetch`, {});
    overlay.classList.remove('show');
    showToast(`${d.new_count} new articles from "${name}"`, 'success');
    await loadFeedTable(); await loadStats(); await loadArticles();
  } catch(e) { overlay.classList.remove('show'); showToast('Fetch failed','error'); }
}

async function bulkToggle(enabled) {
  try {
    await postJSON('/api/feeds/bulk', {enabled});
    await loadFeedTable();
    showToast(enabled ? 'All feeds enabled' : 'All feeds disabled', 'success');
  } catch(e) { showToast('Failed','error'); }
}

let _deleteId = null;
function confirmDelete(id, name) {
  _deleteId = id;
  document.getElementById('modalTitle').textContent = 'Delete Feed';
  document.getElementById('modalBody').textContent  = `Remove "${name}" and all its articles from MongoDB?`;
  document.getElementById('modalConfirm').onclick = doDelete;
  document.getElementById('modalOverlay').classList.add('show');
}
function closeModal() { document.getElementById('modalOverlay').classList.remove('show'); _deleteId=null; }
async function doDelete() {
  const id = _deleteId;
  closeModal();
  try {
    await deleteReq(`/api/feeds/${id}`);
    showToast('Feed deleted','success');
    await loadFeedTable(); await loadStats(); await loadArticles();
  } catch(e) { showToast('Delete failed','error'); }
}

async function fixDates() {
  const btn = document.getElementById('btnFixDates');
  btn.disabled = true; btn.textContent = '⚙ Fixing…';
  try {
    const d = await postJSON('/api/admin/fix-dates', {});
    showToast(`Fixed dates for ${d.migrated} articles`, 'success');
    await loadArticles();
  } catch(e) { showToast('Fix failed', 'error'); }
  finally { btn.disabled = false; btn.textContent = '⚙ Fix Article Dates'; }
}

async function triggerFetchAll() {
  const overlay = document.getElementById('fetchOverlay');
  document.getElementById('fetchStatus').textContent = 'Fetching all enabled feeds…';
  overlay.classList.add('show');
  try {
    const d = await postJSON('/api/fetch', {});
    overlay.classList.remove('show');
    showToast(`${d.total_new} new articles from ${d.sources_fetched} sources`, 'success');
    await loadStats(); await loadArticles();
    if (document.getElementById('pageSources').style.display !== 'none') loadFeedTable();
  } catch(e) { overlay.classList.remove('show'); showToast('Fetch failed','error'); }
}

function handle401(r) {
  if (r.status === 401) {
    window.location.href = '/login';
    return true;
  }
  return false;
}

async function fetchJSON(url) {
  const r = await fetch(url);
  if (handle401(r)) return new Promise(() => {}); // hang forever instead of throwing while redirect happens
  const d = await r.json();
  if (!r.ok) throw new Error(d.error||r.statusText); return d;
}
async function postJSON(url, body) {
  const r = await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})});
  if (handle401(r)) return new Promise(() => {});
  const d = await r.json(); if (!r.ok) throw new Error(d.error||r.statusText); return d;
}
async function patchJSON(url, body) {
  const r = await fetch(url,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})});
  if (handle401(r)) return new Promise(() => {});
  const d = await r.json(); if (!r.ok) throw new Error(d.error||r.statusText); return d;
}
async function deleteReq(url) {
  const r = await fetch(url,{method:'DELETE'});
  if (handle401(r)) return new Promise(() => {});
  const d = await r.json();
  if (!r.ok) throw new Error(d.error||r.statusText); return d;
}

async function logout() {
  try {
    await postJSON('/api/logout');
  } catch(e) {}
  window.location.href = '/login';
}

function esc(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function showToast(msg,type='success') {
  const t = document.getElementById('toast');
  t.textContent=msg; t.className=`toast show ${type}`;
  clearTimeout(t._tid); t._tid=setTimeout(()=>t.className='toast',3500);
}
init();

// ── Settings / Notifications ─────────────────────────────────────────────────

async function loadSettings() {
  try {
    const d = await fetchJSON('/api/settings');
    // Discord
    if (d.discord) {
      document.getElementById('discordUrl').value      = d.discord.webhook_url || d.discord.webhook_url_masked || '';
      document.getElementById('discordEnabled').checked = !!d.discord.enabled;
    }
    // Telegram
    if (d.telegram) {
      document.getElementById('tgToken').value    = d.telegram.token || d.telegram.token_masked || '';
      document.getElementById('tgChatId').value   = d.telegram.chat_id || '';
      document.getElementById('tgEnabled').checked = !!d.telegram.enabled;
    }
    // Scheduler
    if (d.scheduler) {
      document.getElementById('schedHour').value     = d.scheduler.hour   ?? 9;
      document.getElementById('schedMinute').value   = d.scheduler.minute ?? 0;
      document.getElementById('schedEnabled').checked = d.scheduler.enabled !== false;
    }
    // Update sidebar badge
    const anyEnabled = d.discord?.enabled || d.telegram?.enabled;
    document.getElementById('navNotifyBadge').style.display = anyEnabled ? '' : 'none';
  } catch(e) { console.error('loadSettings', e); }
  loadSchedulerStatus();
}

async function loadSchedulerStatus() {
  try {
    const d = await fetchJSON('/api/scheduler/status');
    const info = document.getElementById('schedInfo');
    if (!d.running) {
      info.innerHTML = '<span style="color:var(--red)">● Scheduler not running</span>';
      return;
    }
    const nextHtml = d.next_run
      ? `<div>⏰ Next run: <span class="sched-next">${d.next_run}</span></div>`
      : '<div style="color:var(--muted)">● Auto-fetch disabled</div>';
    info.innerHTML = nextHtml;

    // Runs table
    renderRunsTable(d.recent_runs || []);
  } catch(e) { console.error('loadSchedulerStatus', e); }
}

function renderRunsTable(runs) {
  const tbody = document.getElementById('runsTableBody');
  if (!runs.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty" style="text-align:center;padding:16px;color:var(--muted)">No runs yet</td></tr>';
    return;
  }
  const bkk = 'Asia/Bangkok';
  tbody.innerHTML = runs.map(r => {
    const ts  = r.ran_at ? new Date(r.ran_at).toLocaleString('th-TH', {timeZone: bkk, hour12: false}) : '—';
    const newPill = r.total_new > 0
      ? `<span class="pill new">+${r.total_new}</span>`
      : `<span class="pill none">0</span>`;
    const notPill = r.notified
      ? `<span class="pill sent">✓</span>`
      : `<span class="pill none">—</span>`;
    const disc = r.notify_results?.discord
      ? (r.notify_results.discord.ok ? '<span class="pill sent">✓</span>' : '<span class="pill fail">✗</span>')
      : '<span class="pill none">—</span>';
    const tg   = r.notify_results?.telegram
      ? (r.notify_results.telegram.ok ? '<span class="pill sent">✓</span>' : '<span class="pill fail">✗</span>')
      : '<span class="pill none">—</span>';
    return `<tr>
      <td>${ts}</td>
      <td>${r.sources_fetched ?? '—'}</td>
      <td>${newPill}</td>
      <td>${notPill}</td>
      <td>${disc}</td>
      <td>${tg}</td>
    </tr>`;
  }).join('');
}

async function saveDiscord() {
  const url     = document.getElementById('discordUrl').value.trim();
  const enabled = document.getElementById('discordEnabled').checked;
  try {
    await postJSON('/api/settings', { discord: { webhook_url: url, enabled } });
    showToast('Discord settings saved', 'success');
    document.getElementById('navNotifyBadge').style.display =
      (enabled || document.getElementById('tgEnabled').checked) ? '' : 'none';
  } catch(e) { showToast('Save failed: ' + (e.message||''), 'error'); }
}

async function saveTelegram() {
  const token   = document.getElementById('tgToken').value.trim();
  const chat_id = document.getElementById('tgChatId').value.trim();
  const enabled = document.getElementById('tgEnabled').checked;
  try {
    await postJSON('/api/settings', { telegram: { token, chat_id, enabled } });
    showToast('Telegram settings saved', 'success');
    document.getElementById('navNotifyBadge').style.display =
      (enabled || document.getElementById('discordEnabled').checked) ? '' : 'none';
  } catch(e) { showToast('Save failed: ' + (e.message||''), 'error'); }
}

async function saveScheduler() {
  const hour    = parseInt(document.getElementById('schedHour').value)   || 9;
  const minute  = parseInt(document.getElementById('schedMinute').value) || 0;
  const enabled = document.getElementById('schedEnabled').checked;
  try {
    await postJSON('/api/settings', { scheduler: { hour, minute, enabled } });
    showToast(`Scheduler set to ${String(hour).padStart(2,'0')}:${String(minute).padStart(2,'0')} Bangkok`, 'success');
    setTimeout(loadSchedulerStatus, 800);
  } catch(e) { showToast('Save failed: ' + (e.message||''), 'error'); }
}

async function testDiscord() {
  const url = document.getElementById('discordUrl').value.trim();
  const btn = document.getElementById('btnTestDiscord');
  const dot = document.getElementById('discordDot');
  const msg = document.getElementById('discordMsg');
  btn.disabled = true; btn.textContent = '…';
  dot.className = 'status-dot idle';
  msg.textContent = 'Testing…';
  try {
    const d = await postJSON('/api/notify/test', { channel: 'discord', webhook_url: url });
    dot.className = d.ok ? 'status-dot ok' : 'status-dot err';
    msg.textContent = d.ok ? '✓ Sent!' : '✗ ' + d.msg;
  } catch(e) {
    dot.className = 'status-dot err';
    msg.textContent = '✗ ' + (e.message||'Error');
  }
  btn.disabled = false; btn.textContent = 'Test';
}

async function testTelegram() {
  const token   = document.getElementById('tgToken').value.trim();
  const chat_id = document.getElementById('tgChatId').value.trim();
  const btn = document.getElementById('btnTestTg');
  const dot = document.getElementById('tgDot');
  const msg = document.getElementById('tgMsg');
  btn.disabled = true; btn.textContent = '…';
  dot.className = 'status-dot idle';
  msg.textContent = 'Testing…';
  try {
    const d = await postJSON('/api/notify/test', { channel: 'telegram', token, chat_id });
    dot.className = d.ok ? 'status-dot ok' : 'status-dot err';
    msg.textContent = d.ok ? '✓ Sent!' : '✗ ' + d.msg;
  } catch(e) {
    dot.className = 'status-dot err';
    msg.textContent = '✗ ' + (e.message||'Error');
  }
  btn.disabled = false; btn.textContent = 'Test';
}

async function findChatId(e) {
  e.preventDefault();
  const token = document.getElementById('tgToken').value.trim();
  if (!token) { showToast('Enter Bot Token first', 'error'); return; }
  try {
    const d = await postJSON('/api/notify/test', { channel: 'telegram_find_chatid', token });
    showToast(d.msg, d.ok ? 'success' : 'error');
  } catch(err) { showToast(err.message||'Error', 'error'); }
}

async function runNow() {
  try {
    await postJSON('/api/scheduler/run', {});
    showToast('Fetch triggered! Check runs table in a moment.', 'success');
    setTimeout(loadSchedulerStatus, 8000);
  } catch(e) { showToast('Failed: '+(e.message||''), 'error'); }
}
</script>
</body>
</html>"""

# ─── API handlers ─────────────────────────────────────────────────────────────

# Keywords for each category — matched against title + summary (case-insensitive)
CATEGORY_KEYWORDS: dict = {
    "ransomware":    ["ransomware", "ransom", "encrypt.*file", "decrypt.*key", "lockbit", "blackcat", "cl0p", "conti", "ryuk", "revil", "darkside", "blackbasta"],
    "databreach":   ["data breach", "data leak", "leaked data", "exposed data", "личные данные", "ข้อมูลหลุด", "ข้อมูลรั่ว", "personal data", "pii", "credentials leak", "database leak", "millions of records"],
    "vulnerability": ["vulnerability", "cve-", "zero.?day", "rce", "remote code execution", "critical flaw", "patch", "exploit", "cvss", "buffer overflow", "sql injection", "xss"],
    "malware":      ["malware", "trojan", "backdoor", "spyware", "rootkit", "worm", "virus", "infostealer", "keylogger", "botnet", "rat ", "remote access tool"],
    "apt":          ["apt", "nation.?state", "espionage", "cyber espionage", "apt4[0-9]", "lazarus", "fancy bear", "cozy bear", "volt typhoon", "salt typhoon", "mustang panda"],
    "phishing":     ["phishing", "spear.?phishing", "smishing", "vishing", "business email compromise", "bec", "credential harvest", "fake login"],
    "other":        [],  # "other" = articles that don't match any above category
}


def _category_filter(category: str) -> dict:
    """Build a MongoDB $or filter for a category based on its keywords."""
    if category == "other":
        # Exclude articles matching ANY known category
        all_kw = [kw for cat, kws in CATEGORY_KEYWORDS.items() if cat != "other" for kw in kws]
        conditions = [{"title": {"$regex": kw, "$options": "i"}} for kw in all_kw]
        conditions += [{"summary": {"$regex": kw, "$options": "i"}} for kw in all_kw]
        return {"$nor": conditions}
    kws = CATEGORY_KEYWORDS.get(category, [])
    if not kws:
        return {}
    conditions = [{"title": {"$regex": kw, "$options": "i"}} for kw in kws]
    conditions += [{"summary": {"$regex": kw, "$options": "i"}} for kw in kws]
    return {"$or": conditions}


def api_articles(params: dict) -> dict:
    # [SECURITY] Clamp page and per_page to valid ranges
    try:
        page     = max(1, int(params.get("page",     ["1"])[0]))
        per_page = max(1, min(200, int(params.get("per_page", ["50"])[0])))
    except (ValueError, TypeError):
        page, per_page = 1, 50

    # [SECURITY] Whitelist sort values
    sort_raw = params.get("sort", ["published"])[0]
    sort     = sort_raw if sort_raw in ("published", "fetched_at") else "published"

    source      = params.get("source",    [None])[0]
    q           = params.get("q",         [None])[0]
    date_from   = params.get("date_from", [None])[0]
    date_to     = params.get("date_to",   [None])[0]
    sources_str = params.get("sources",   [None])[0]   # comma-separated
    category    = params.get("category",  [None])[0]   # category key

    # [SECURITY] Cap search query length to limit regex complexity (ReDoS mitigation)
    if q:
        q = q[:200]

    filt = {}

    # Source filter — multi-select takes priority over single
    if sources_str:
        src_list = [s.strip() for s in sources_str.split(",") if s.strip()]
        if src_list:
            filt["source"] = {"$in": src_list}
    elif source:
        filt["source"] = source

    # Full-text search
    if q:
        filt["$or"] = [
            {"title":   {"$regex": q, "$options": "i"}},
            {"summary": {"$regex": q, "$options": "i"}},
        ]

    # Category filter — merge with $and if needed
    if category and category in CATEGORY_KEYWORDS:
        cat_filt = _category_filter(category)
        if cat_filt:
            if "$and" in filt:
                filt["$and"].append(cat_filt)
            else:
                filt["$and"] = [cat_filt]

    # Date range — use published_dt (UTC datetime) for reliable comparison
    if date_from or date_to:
        date_filt = {}
        if date_from:
            date_filt["$gte"] = datetime.strptime(date_from, "%Y-%m-%d").replace(tzinfo=None)
        if date_to:
            date_filt["$lte"] = datetime.strptime(date_to, "%Y-%m-%d").replace(
                hour=23, minute=59, second=59, tzinfo=None)
        filt["published_dt"] = date_filt

    sort_field = "published_dt" if sort == "published" else "fetched_at"
    db     = get_db()

    if not filt:
        total = db.articles.estimated_document_count()
    else:
        total  = db.articles.count_documents(filt)

    cursor = db.articles.find(
        filt,
        {"_id": 0, "source": 1, "title": 1, "url": 1, "summary": 1, "published": 1},
    ).sort(sort_field, DESCENDING).skip((page - 1) * per_page).limit(per_page)

    return {"total": total, "page": page, "per_page": per_page,
            "articles": list(cursor)}


_stats_cache = {"ts": 0, "data": None}

def api_stats() -> dict:
    import time
    now = time.monotonic()
    if _stats_cache["data"] and now - _stats_cache["ts"] < 300:
        return _stats_cache["data"]

    db         = get_db()
    total      = db.articles.estimated_document_count()
    feed_count = db.feeds.count_documents({})
    pipeline   = [
        {"$group": {"_id": "$source", "count": {"$sum": 1}}},
        {"$sort":  {"count": DESCENDING}},
        {"$project": {"source": "$_id", "count": 1, "_id": 0}},
    ]
    data = {"total": total, "feed_count": feed_count,
            "sources": list(db.articles.aggregate(pipeline))}
    _stats_cache["ts"] = now
    _stats_cache["data"] = data
    return data


def api_get_feeds() -> list:
    db       = get_db()
    pipeline = [
        {"$lookup": {
            "from": "articles",
            "let":  {"feedName": "$name"},
            "pipeline": [
                {"$match": {"$expr": {"$eq": ["$source", "$$feedName"]}}},
                {"$count": "n"},
            ],
            "as": "stats",
        }},
        {"$addFields": {
            "article_count": {"$ifNull": [{"$arrayElemAt": ["$stats.n", 0]}, 0]},
            "id": {"$toString": "$_id"},
        }},
        {"$project": {"_id": 0, "stats": 0}},
        {"$sort": {"name": 1}},
    ]
    return list(db.feeds.aggregate(pipeline))


def api_add_feed(body: dict) -> dict:
    name = (body.get("name") or "").strip()
    url  = (body.get("url")  or "").strip()
    if not name or not url:
        raise ValueError("name and url are required")
    if len(name) > 120:
        raise ValueError("name too long (max 120 chars)")
    if len(url) > 1024:
        raise ValueError("url too long (max 1024 chars)")
    # [SECURITY] Only allow http/https schemes for feed URLs
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http/https URLs are allowed")
    db  = get_db()
    now = datetime.now(timezone.utc)
    try:
        result = db.feeds.insert_one(
            {"name": name, "url": url, "enabled": True,
             "last_fetch": None, "created_at": now}
        )
    except DuplicateKeyError:
        raise ValueError("A feed with that name already exists")
    return {"id": str(result.inserted_id), "name": name, "url": url}


def api_test_feed(body: dict) -> dict:
    url = (body.get("url") or "").strip()
    if not url:
        raise ValueError("url is required")
    # [SECURITY] Only allow http/https schemes
    parsed_url = urlparse(url)
    if parsed_url.scheme not in ("http", "https"):
        raise ValueError("Only http/https URLs are allowed")
    data = fetch_url(url, timeout=10)
    if data is None:
        raise ValueError("Could not fetch URL — check it is reachable")
    articles = parse_rss(data, "test")
    if not articles:
        raise ValueError("No articles found — is this an RSS/Atom feed URL?")
    return {"count": len(articles), "sample": (articles[0]["title"] or "")[:80]}


def api_toggle_feed(fid: str, body: dict) -> dict:
    db      = get_db()
    enabled = bool(body.get("enabled"))
    db.feeds.update_one({"_id": oid(fid)}, {"$set": {"enabled": enabled}})
    return {"ok": True}


def api_fetch_one(fid: str) -> dict:
    db   = get_db()
    feed = db.feeds.find_one({"_id": oid(fid)}, {"name": 1, "url": 1})
    if not feed:
        raise ValueError("Feed not found")
    arts                 = fetch_feed(feed["name"], feed["url"])
    new_count, new_arts  = save_articles(db, arts)
    db.feeds.update_one({"_id": oid(fid)},
                        {"$set": {"last_fetch": datetime.now(timezone.utc)}})
    notify_results = notify_new_articles(db, new_arts) if new_arts else {}
    return {"new_count": new_count, "total": len(arts), "notify": notify_results}


def api_delete_feed(fid: str) -> dict:
    db   = get_db()
    feed = db.feeds.find_one({"_id": oid(fid)}, {"name": 1})
    if not feed:
        raise ValueError("Feed not found")
    db.articles.delete_many({"source": feed["name"]})
    db.feeds.delete_one({"_id": oid(fid)})
    return {"ok": True}


def api_bulk_toggle(body: dict) -> dict:
    enabled = bool(body.get("enabled"))
    get_db().feeds.update_many({}, {"$set": {"enabled": enabled}})
    return {"ok": True}


# ─── Settings / Notifications APIs ───────────────────────────────────────────

def api_get_settings() -> dict:
    db  = get_db()
    doc = db.settings.find_one({"_id": "notifications"}) or {}
    doc.pop("_id", None)
    # Mask secrets
    if "discord" in doc and doc["discord"].get("webhook_url"):
        url = doc["discord"]["webhook_url"]
        doc["discord"]["webhook_url_masked"] = url[:40] + "…" if len(url) > 40 else url
    if "telegram" in doc and doc["telegram"].get("token"):
        t = doc["telegram"]["token"]
        doc["telegram"]["token_masked"] = t[:8] + "…"
    return doc


def api_save_settings(body: dict) -> dict:
    db  = get_db()
    doc = db.settings.find_one({"_id": "notifications"}) or {"_id": "notifications"}

    if "discord" in body:
        disc = doc.setdefault("discord", {})
        if "webhook_url" in body["discord"] and body["discord"]["webhook_url"]:
            wh_url = str(body["discord"]["webhook_url"]).strip()
            # [SECURITY] SSRF prevention — only allow real Discord webhook URLs
            if not wh_url.startswith("https://discord.com/api/webhooks/"):
                raise ValueError("Invalid Discord webhook URL")
            disc["webhook_url"] = wh_url
        if "enabled" in body["discord"]:
            disc["enabled"] = bool(body["discord"]["enabled"])

    if "telegram" in body:
        tg = doc.setdefault("telegram", {})
        if "token" in body["telegram"] and body["telegram"]["token"]:
            token = str(body["telegram"]["token"]).strip()
            # [SECURITY] Basic Telegram token format: digits:alphanum
            if not re.match(r'^\d+:[A-Za-z0-9_-]{35,}$', token):
                raise ValueError("Invalid Telegram bot token format")
            tg["token"] = token
        if "chat_id" in body["telegram"] and body["telegram"]["chat_id"]:
            chat_id = str(body["telegram"]["chat_id"]).strip()
            # [SECURITY] chat_id is numeric (possibly negative) or @channel
            if not re.match(r'^-?\d+$|^@[A-Za-z0-9_]{5,}$', chat_id):
                raise ValueError("Invalid Telegram chat_id format")
            tg["chat_id"] = chat_id
        if "enabled" in body["telegram"]:
            tg["enabled"] = bool(body["telegram"]["enabled"])

    if "scheduler" in body:
        sc = doc.setdefault("scheduler", {})
        if "hour"    in body["scheduler"]:
            h = int(body["scheduler"]["hour"])
            if not 0 <= h <= 23: raise ValueError("hour must be 0-23")
            sc["hour"] = h
        if "minute"  in body["scheduler"]:
            m = int(body["scheduler"]["minute"])
            if not 0 <= m <= 59: raise ValueError("minute must be 0-59")
            sc["minute"] = m
        if "enabled" in body["scheduler"]: sc["enabled"] = bool(body["scheduler"]["enabled"])
        # Hot-reload scheduler
        sched.reconfigure(
            hour    = sc.get("hour",    9),
            minute  = sc.get("minute",  0),
            tz_str  = "Asia/Bangkok",
            enabled = sc.get("enabled", True),
        )

    db.settings.replace_one({"_id": "notifications"}, doc, upsert=True)
    return {"ok": True}


def api_test_notify(body: dict) -> dict:
    db      = get_db()
    channel = body.get("channel", "")        # "discord" or "telegram"
    doc     = db.settings.find_one({"_id": "notifications"}) or {}

    if channel == "discord":
        url = body.get("webhook_url") or (doc.get("discord") or {}).get("webhook_url", "")
        ok, msg = test_discord(url)
        return {"ok": ok, "msg": msg}

    elif channel == "telegram":
        token   = body.get("token")   or (doc.get("telegram") or {}).get("token", "")
        chat_id = body.get("chat_id") or (doc.get("telegram") or {}).get("chat_id", "")
        ok, msg = test_telegram(token, chat_id)
        return {"ok": ok, "msg": msg}

    elif channel == "telegram_find_chatid":
        token = body.get("token") or (doc.get("telegram") or {}).get("token", "")
        ok, msg = get_telegram_updates(token)
        return {"ok": ok, "msg": msg}

    raise ValueError(f"Unknown channel: {channel}")


def api_scheduler_status() -> dict:
    db = get_db()
    return sched.get_status(db)


def api_run_now() -> dict:
    sched.run_now()
    return {"ok": True, "msg": "Triggered fetch in background"}


def api_migrate_dates() -> dict:
    """Back-fill published_dt for articles that don't have it yet."""
    from security_news import to_datetime
    db      = get_db()
    cursor  = db.articles.find(
        {"published_dt": {"$exists": False}, "published": {"$ne": None}},
        {"_id": 1, "published": 1},
    )
    updated = 0
    for doc in cursor:
        dt = to_datetime(doc.get("published"))
        db.articles.update_one({"_id": doc["_id"]}, {"$set": {"published_dt": dt}})
        updated += 1
    return {"migrated": updated}


def api_fetch_all() -> dict:
    db         = get_db()
    feeds      = list(db.feeds.find({"enabled": True}, {"name": 1, "url": 1}))
    total_new  = 0
    all_new    = []
    now        = datetime.now(timezone.utc)
    for feed in feeds:
        arts     = fetch_feed(feed["name"], feed["url"])
        cnt, new = save_articles(db, arts)
        total_new += cnt
        all_new   += new
        db.feeds.update_one({"_id": feed["_id"]}, {"$set": {"last_fetch": now}})
    notify_results = notify_new_articles(db, all_new) if all_new else {}
    return {"total_new": total_new, "sources_fetched": len(feeds),
            "notify": notify_results}


# ─── HTTP handler ─────────────────────────────────────────────────────────────

OID_RE  = r"[a-f0-9]{24}"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.info("%s %s", self.address_string(), fmt % args)

    # ── Security helpers ──────────────────────────────────────────────────────

    def _add_security_headers(self):
        for k, v in _SECURITY_HEADERS.items():
            self.send_header(k, v)

    def _read_cookies(self) -> dict:
        cookies = {}
        cookie_header = self.headers.get("Cookie")
        if cookie_header:
            for item in cookie_header.split(";"):
                parts = item.strip().split("=", 1)
                if len(parts) == 2:
                    cookies[parts[0]] = parts[1]
        return cookies

    def _sign_cookie(self, data: str) -> str:
        sig = hmac.new(_SESSION_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()
        return f"{data}.{sig}"

    def _verify_cookie(self, cookie_val: str) -> bool:
        if not cookie_val or "." not in cookie_val:
            return False
        data, sig = cookie_val.rsplit(".", 1)
        expected_sig = hmac.new(_SESSION_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected_sig)

    def _check_auth(self) -> bool:
        """Return True if session passes (or auth is disabled)."""
        if not _AUTH_ENABLED:
            return True
        cookies = self._read_cookies()
        session_val = cookies.get("secnews_session")
        return self._verify_cookie(session_val)

    def _require_auth(self) -> bool:
        """Send 401/302 and return False if auth fails."""
        if not self._check_auth():
            if self.path.startswith("/api/"):
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self._add_security_headers()
                self.end_headers()
                self.wfile.write(b'{"error":"Unauthorized"}')
            else:
                self.send_response(302)
                self.send_header("Location", "/login")
                self._add_security_headers()
                self.end_headers()
            return False
        return True

    def _get_client_ip(self) -> str:
        """Get client IP, resolving X-Forwarded-For or X-Real-IP if behind reverse proxy."""
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        real_ip = self.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
        return self.client_address[0]

    def _check_rate_limit(self) -> bool:
        """Send 429 and return False if rate limit exceeded."""
        ip = self._get_client_ip()
        if not _check_rate(ip):
            log.warning("Rate limit exceeded for %s", ip)
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("Retry-After", str(_RATE_WINDOW))
            self._add_security_headers()
            self.end_headers()
            self.wfile.write(b'{"error":"Too many requests"}')
            return False
        return True

    # ── Response senders ─────────────────────────────────────────────────────

    def send_json(self, data, status: int = 200):
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self._add_security_headers()
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html: str):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self._add_security_headers()
        self.end_headers()
        self.wfile.write(body)

    def read_body(self) -> dict:
        # [SECURITY] Enforce max body size to prevent OOM
        raw_len = self.headers.get("Content-Length", "0")
        try:
            n = int(raw_len)
        except ValueError:
            n = 0
        if n < 0 or n > MAX_BODY_BYTES:
            raise ValueError(f"Request body too large (max {MAX_BODY_BYTES // 1024} KB)")
        return json.loads(self.rfile.read(n)) if n else {}

    # ── HTTP verbs ────────────────────────────────────────────────────────────

    def do_GET(self):
        if not self._check_rate_limit(): return
        parsed = urlparse(self.path)
        path   = parsed.path
        
        # Public route
        if path == "/login":
            if self._check_auth():
                self.send_response(302)
                self.send_header("Location", "/")
                self.end_headers()
                return
            self.send_html(LOGIN_HTML)
            return

        if not self._require_auth():     return
        params = parse_qs(parsed.query)
        try:
            if   path == "/":                      self.send_html(HTML)
            elif path == "/api/articles":          self.send_json(api_articles(params))
            elif path == "/api/stats":             self.send_json(api_stats())
            elif path == "/api/feeds":             self.send_json(api_get_feeds())
            elif path == "/api/settings":          self.send_json(api_get_settings())
            elif path == "/api/scheduler/status":  self.send_json(api_scheduler_status())
            else:                                  self.send_json({"error": "not found"}, 404)
        except ValueError as e:
            self.send_json({"error": str(e)}, 400)
        except Exception as e:
            log.exception("GET %s unhandled error", path)
            self.send_json({"error": "Internal server error"}, 500)

    def do_POST(self):
        if not self._check_rate_limit(): return
        path = urlparse(self.path).path
        try:
            body = self.read_body()
        except (ValueError, json.JSONDecodeError) as e:
            self.send_json({"error": str(e)}, 400)
            return

        if path == "/api/login":
            user = body.get("username", "")
            pwd  = body.get("password", "")
            if _AUTH_ENABLED and hmac.compare_digest(user, _ADMIN_USER) and hmac.compare_digest(pwd, _ADMIN_PASS):
                val = self._sign_cookie("auth_ok")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"secnews_session={val}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax")
                self._add_security_headers()
                self.end_headers()
                self.wfile.write(b'{"ok":true}')
            elif not _AUTH_ENABLED:
                self.send_json({"error": "Auth is disabled, no login required."}, 400)
            else:
                self.send_json({"error": "Invalid credentials"}, 401)
            return
            
        if path == "/api/logout":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "secnews_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax")
            self._add_security_headers()
            self.end_headers()
            self.wfile.write(b'{"ok":true}')
            return

        if not self._require_auth():     return

        try:
            if   path == "/api/fetch":           self.send_json(api_fetch_all())
            elif path == "/api/feeds":           self.send_json(api_add_feed(body), 201)
            elif path == "/api/feeds/test":      self.send_json(api_test_feed(body))
            elif path == "/api/feeds/bulk":      self.send_json(api_bulk_toggle(body))
            elif path == "/api/settings":        self.send_json(api_save_settings(body))
            elif path == "/api/notify/test":     self.send_json(api_test_notify(body))
            elif path == "/api/scheduler/run":   self.send_json(api_run_now())
            elif path == "/api/admin/fix-dates": self.send_json(api_migrate_dates())
            else:
                m = re.match(rf"^/api/feeds/({OID_RE})/fetch$", path)
                if m: self.send_json(api_fetch_one(m.group(1)))
                else: self.send_json({"error": "not found"}, 404)
        except ValueError as e:
            self.send_json({"error": str(e)}, 400)
        except Exception as e:
            log.exception("POST %s unhandled error", path)
            self.send_json({"error": "Internal server error"}, 500)

    def do_PATCH(self):
        if not self._check_rate_limit(): return
        if not self._require_auth():     return
        path = urlparse(self.path).path
        try:
            body = self.read_body()
        except (ValueError, json.JSONDecodeError) as e:
            self.send_json({"error": str(e)}, 400)
            return
        m = re.match(rf"^/api/feeds/({OID_RE})$", path)
        if m:
            try:    self.send_json(api_toggle_feed(m.group(1), body))
            except ValueError as e: self.send_json({"error": str(e)}, 400)
            except Exception as e:
                log.exception("PATCH %s unhandled error", path)
                self.send_json({"error": "Internal server error"}, 500)
        else:
            self.send_json({"error": "not found"}, 404)

    def do_DELETE(self):
        if not self._check_rate_limit(): return
        if not self._require_auth():     return
        path = urlparse(self.path).path
        m = re.match(rf"^/api/feeds/({OID_RE})$", path)
        if m:
            try:    self.send_json(api_delete_feed(m.group(1)))
            except ValueError as e: self.send_json({"error": str(e)}, 404)
            except Exception as e:
                log.exception("DELETE %s unhandled error", path)
                self.send_json({"error": "Internal server error"}, 500)
        else:
            self.send_json({"error": "not found"}, 404)


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Security News Web UI (MongoDB)")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    db = get_db()
    init_collections(db)

    # Start background scheduler (read config from DB if saved)
    sc_doc  = (db.settings.find_one({"_id": "notifications"}) or {}).get("scheduler", {})
    sched.start_scheduler(
        get_db  = get_db,
        hour    = sc_doc.get("hour",    9),
        minute  = sc_doc.get("minute",  0),
        tz_str  = "Asia/Bangkok",
        enabled = sc_doc.get("enabled", True),
    )

    if not _AUTH_ENABLED:
        log.warning(
            "⚠️  ADMIN_USER / ADMIN_PASS not set — running WITHOUT authentication! "
            "Set both env vars to enable HTTP Basic Auth."
        )
    else:
        log.info("HTTP Basic Auth enabled for user '%s'", _ADMIN_USER)

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Security News Monitor → http://{args.host}:{args.port}")
    print(f"MongoDB: {MONGO_URI}/{DB_NAME}")
    print(f"Auth: {'ENABLED (user: ' + _ADMIN_USER + ')' if _AUTH_ENABLED else 'DISABLED (set ADMIN_USER + ADMIN_PASS to enable)'}")
    print(f"Rate limit: {_RATE_LIMIT} req/min per IP")
    print("Scheduler: daily fetch 09:00 Asia/Bangkok")
    print("Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
