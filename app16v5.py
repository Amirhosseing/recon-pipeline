import os
import json
import logging
import threading
import functools
import subprocess
import zipfile
import io
import shutil
import socket
import glob
import csv
import time
import shlex
import requests
import tempfile
import uuid
import xml.etree.ElementTree as ET 
from pathlib import Path
from datetime import datetime, timedelta
from urllib.parse import urlparse
from bson import ObjectId
from typing import List, Dict, Any, Optional, Tuple

# Dependencies
from pymongo import MongoClient, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError, DuplicateKeyError
from flask import Flask, render_template_string, request, jsonify, send_file, session, redirect, url_for, abort
from flask.json.provider import DefaultJSONProvider
from flask_socketio import SocketIO, emit, join_room
from werkzeug.utils import secure_filename

# --- Configuration & Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(name)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("ReconPipeline")

app = Flask(__name__)
# WARNING: In production, SECRET_KEY must be injected via environment variables.
app.secret_key = os.environ.get('SECRET_KEY', 'super_secret_key_change_in_prod')
if app.secret_key == 'super_secret_key_change_in_prod':
    logger.warning("SECURITY WARNING: Running with default SECRET_KEY. Please set SECRET_KEY environment variable in production.")

socketio = SocketIO(app, cors_allowed_origins="*")

# Telegram Config - MUST be set via environment variables
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')

# Validate Telegram config
if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
    logger.warning("⚠️ Telegram notifications disabled: TELEGRAM_BOT_TOKEN and/or TELEGRAM_CHAT_ID not set.")

# Custom JSON Provider for MongoDB ObjectIds and Datetimes
class MongoJSONProvider(DefaultJSONProvider):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, ObjectId): return str(obj)
        if isinstance(obj, datetime): return obj.isoformat()
        return super().default(obj)

app.json = MongoJSONProvider(app)

# Credentials
ADMIN_USERNAME = os.environ.get('ADMIN_USER', 'administrator')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASS', 'Qwer12#$')
if ADMIN_PASSWORD == 'Qwer12#$':
    logger.warning("SECURITY WARNING: Running with default ADMIN_PASSWORD. Please set ADMIN_PASS environment variable in production.")

# MongoDB Config
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = os.environ.get("DB_NAME", "recon_pipeline")

# Tool Configuration
REQUIRED_TOOLS = ['subfinder', 'puredns', 'dnsx', 'cut-cdn', 'tlsx', 'httpx', 'katana', 'nmap', 'nuclei', 'ffuf', 'gowitness']

# Globals
scan_queue: Dict[str, Any] = {}

# --- Database Setup ---
try:
    logger.info(f"Connecting to MongoDB at {MONGO_URI}...")
    mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    # Force connection check
    mongo_client.admin.command('ping')
    db = mongo_client[DB_NAME]
    
    # Indexes
    db.scans.create_index([("scan_id", DESCENDING)], unique=True)
    db.scans.create_index([("status", 1), ("scheduled_time", 1)])
    db.scans.create_index([("targets", 1), ("created_at", -1)]) 
    db.saved_targets.create_index([("value", 1)], unique=True)
    db.known_subdomains.create_index([("subdomain", 1)], unique=True)
    
    logger.info("✅ Successfully connected to MongoDB")
    
    # Fix stuck scans on restart
    result = db.scans.update_many(
        {'status': 'running'},
        {'$set': {'status': 'interrupted', 'error': 'Server restarted during scan'}}
    )
    if result.modified_count > 0:
        logger.info(f"🔄 Reset {result.modified_count} stuck scans to 'interrupted' state.")
except (ConnectionFailure, ServerSelectionTimeoutError) as e:
    logger.critical(f"❌ Failed to connect to MongoDB: {e}")
    # In a strict production environment, we might sys.exit(1) here.
except Exception as e:
    logger.critical(f"❌ Unexpected database initialization error: {e}")

# --- Smart Binary Resolver ---
@functools.lru_cache(maxsize=32)
def get_tool_path(tool_name: str) -> str:
    """Resolves the absolute path to a tool binary, with caching for performance."""
    path = shutil.which(tool_name)
    if path: return path
    
    possible_paths = [
        f"/usr/local/bin/{tool_name}", f"/usr/bin/{tool_name}", f"/bin/{tool_name}",
        os.path.expanduser(f"~/go/bin/{tool_name}"), os.path.expanduser(f"~/.local/bin/{tool_name}"),
        f"/root/go/bin/{tool_name}", f"/usr/local/go/bin/{tool_name}"
    ]
    if os.environ.get("GOPATH"): 
        possible_paths.append(f"{os.environ.get('GOPATH')}/bin/{tool_name}")
    
    for p in possible_paths:
        if os.path.exists(p) and os.access(p, os.X_OK): 
            return p
            
    return tool_name

def check_dependencies():
    """Validates that all required external tools are available in the system PATH."""
    missing = []
    for tool in REQUIRED_TOOLS:
        path = get_tool_path(tool)
        if path == tool and not shutil.which(tool): 
            missing.append(tool)
    if missing: 
        logger.warning(f"⚠️  MISSING TOOLS DETECTED: {', '.join(missing)}. Some pipeline stages will fail.")
    else:
        logger.info("✅ All required tools are installed and accessible.")

# --- Utility Functions ---
def parse_json_lines_helper(file_path: Path) -> List[Dict]:
    """Safely parses a JSONL file, ignoring malformed lines."""
    results = []
    if not file_path.exists(): 
        return results
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if line.strip():
                    try: 
                        results.append(json.loads(line))
                    except json.JSONDecodeError: 
                        continue
    except Exception as e:
        logger.error(f"Error reading JSON lines from {file_path}: {e}")
    return results

def count_file_lines(file_path: Path) -> int:
    """Counts lines in a file efficiently without loading into memory."""
    if not file_path.exists(): 
        return 0
    count = 0
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for _ in f: count += 1
    except Exception as e: 
        logger.error(f"Error counting lines for {file_path}: {e}")
    return count

def generate_unique_scan_id() -> str:
    """Generates a unique scan ID using timestamp + short UUID to avoid collisions."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    short_uuid = uuid.uuid4().hex[:6]
    return f"{timestamp}_{short_uuid}"

# --- TELEGRAM HELPER ---
def send_telegram_alert(message: str) -> bool:
    """Sends a Telegram alert. Returns False if not configured or on error."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.debug("Telegram not configured, skipping alert.")
        return False
    
    # Validate token format (basic check)
   # if not TELEGRAM_BOT_TOKEN.count(':') >= 1 or len(TELEGRAM_BOT_TOKEN) < 40:
    #    logger.warning("Invalid Telegram bot token format, skipping alert.")
     #   return False
    
    proxies = {"http": "socks5://127.0.0.1:9050", "https": "socks5://127.0.0.1:9050"}
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}
    
    try:
        response = requests.post(url, json=payload, proxies=proxies, timeout=30)
        print(response.text)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e: 
        logger.error(f"Failed to send Telegram alert: {e}")
        return False

def send_telegram_document(file_path: str, caption: Optional[str] = None) -> bool:
    """Sends a document via Telegram. Returns False if not configured or on error."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID: 
        return False
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0: 
        return False
    
    # Validate token format (basic check)
    if not TELEGRAM_BOT_TOKEN.count(':') >= 1 or len(TELEGRAM_BOT_TOKEN) < 40:
        logger.warning("Invalid Telegram bot token format, skipping document upload.")
        return False
    
    proxies = {"http": "socks5://127.0.0.1:9050", "https": "socks5://127.0.0.1:9050"}
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
    data = {"chat_id": TELEGRAM_CHAT_ID}
    if caption: data["caption"] = caption
    
    for attempt in range(1, 4):
        try:
            with open(file_path, 'rb') as f:
                response = requests.post(url, data=data, files={'document': f}, proxies=proxies, timeout=120)
                response.raise_for_status()
                return True
        except requests.exceptions.RequestException as e:
            logger.warning(f"Telegram document upload attempt {attempt} failed: {e}")
            time.sleep(2)
        except Exception as e:
            logger.error(f"Unexpected error uploading Telegram document: {e}")
            break
    return False

# --- TEMPLATES ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Recon Pipeline</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/atom-one-dark.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: rgba(255, 255, 255, 0.95); padding: 30px; border-radius: 15px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2); margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }
        h1 { color: #667eea; margin-bottom: 10px; font-size: 2.5em; }
        .subtitle { color: #666; font-size: 1.1em; }
        .logout-btn { background: #f44336; color: white; padding: 10px 20px; border: none; border-radius: 8px; font-size: 14px; cursor: pointer; transition: background 0.3s; text-decoration: none;}
        .logout-btn:hover { background: #d32f2f; }
        .main-content { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
        @media (max-width: 768px) { .main-content { grid-template-columns: 1fr; } .checkbox-group { grid-template-columns: 1fr; } }
        .card { background: rgba(255, 255, 255, 0.95); padding: 25px; border-radius: 15px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2); }
        .card h2 { color: #667eea; margin-bottom: 20px; font-size: 1.5em; display: flex; align-items: center; justify-content: space-between; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; color: #333; font-weight: 600; }
        input[type="text"], textarea, input[type="file"], select, input[type="datetime-local"], input[type="date"] { width: 100%; padding: 12px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 14px; }
        .checkbox-group { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px; margin-top: 10px; }
        .checkbox-item { display: flex; align-items: center; }
        .checkbox-item input[type="checkbox"], .checkbox-item input[type="radio"] { margin-right: 8px; width: 18px; height: 18px; cursor: pointer; }
        .btn { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; border: none; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; width: 100%; transition: transform 0.2s; }
        .btn:hover { transform: translateY(-2px); }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .pipeline-stages { display: flex; flex-direction: column; gap: 15px; }
        .stage { background: #f5f5f5; padding: 15px; border-radius: 8px; border-left: 4px solid #ddd; }
        .stage.running { border-left-color: #667eea; background: #e8eaf6; }
        .stage.completed { border-left-color: #4caf50; background: #e8f5e9; }
        .stage.error { border-left-color: #f44336; background: #ffebee; }
        .stage-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
        .progress-wrapper { margin-top: 10px; background: #e0e0e0; border-radius: 4px; height: 6px; overflow: hidden; }
        .progress-fill { height: 100%; background: #4caf50; width: 0%; transition: width 0.4s ease; }
        .stage.running .progress-fill { background: #667eea; }
        .results-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-top: 20px; }
        .result-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }
        .history-table { width: 100%; border-collapse: collapse; font-size: 14px; margin-top: 10px; }
        .history-table th, .history-table td { text-align: left; padding: 12px; border-bottom: 1px solid #eee; }
        .view-btn { padding: 6px 12px; font-size: 12px; background: #667eea; color: white; border: none; border-radius: 4px; cursor: pointer; margin-right: 5px;}
        .delete-btn { padding: 6px 12px; font-size: 12px; background: #f44336; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .stop-btn { padding: 6px 12px; font-size: 12px; background: #ff9800; color: white; border: none; border-radius: 4px; cursor: pointer; margin-right: 5px;}
        .resume-btn { padding: 6px 12px; font-size: 12px; background: #4caf50; color: white; border: none; border-radius: 4px; cursor: pointer; margin-right: 5px;}
        
        .advanced-config { margin-top: 15px; border: 1px solid #ddd; border-radius: 8px; overflow: hidden; }
        .advanced-header { background: #f5f5f5; padding: 10px 15px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; font-weight: 600; color: #333; }
        .advanced-body { padding: 15px; display: none; background: #fff; }
        .advanced-body.show { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }

        /* Modal and JSON Viewer Styles */
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.5); }
        .modal-content { background-color: #fefefe; margin: 5% auto; padding: 20px; border: 1px solid #888; width: 80%; max-height: 80vh; overflow-y: hidden; border-radius: 10px; display: flex; flex-direction: column; }
        .close { color: #aaa; float: right; font-size: 28px; font-weight: bold; cursor: pointer; align-self: flex-end; }
        .close:hover, .close:focus { color: black; text-decoration: none; }
        .modal-content pre {
            background: #282c34; color: #abb2bf; padding: 1em; border-radius: 5px;
            max-height: 65vh; overflow: auto; flex-grow: 1; margin-top: 15px;
        }
        .modal-content code { font-family: 'Courier New', Courier, monospace; font-size: 14px; white-space: pre; }
        
        .file-tag {
            display: inline-block; padding: 6px 12px; margin: 5px; background: #f0f4f8;
            border: 1px solid #d1d9e6; border-radius: 4px; color: #333; font-size: 13px;
            cursor: pointer; transition: all 0.2s; text-decoration: none;
        }
        .file-tag:hover { background: #667eea; color: white; border-color: #667eea; }
        .download-buttons { display: flex; gap: 15px; margin-top: 15px; }
        .download-btn { width: auto; flex: 1; }
        .pagination-controls { margin-top: 15px; display: flex; justify-content: flex-end; align-items: center; gap: 10px; }
        .pagination-controls button { width: auto; }
        
        /* --- Dashboard & Tabs CSS --- */
        .nav-tabs { display: flex; gap: 15px; margin-bottom: 20px; border-bottom: 2px solid #ddd; padding-bottom: 10px; }
        .nav-btn { background: none; border: none; font-size: 18px; font-weight: 600; color: #666; cursor: pointer; padding: 10px 20px; border-radius: 8px; transition: all 0.3s; }
        .nav-btn:hover { background: #f0f4f8; color: #667eea; }
        .nav-btn.active { background: #667eea; color: white; box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3); }
        
        .dashboard-container { display: none; } /* Hidden by default */
        .dashboard-container.active { display: block; }
        
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-box { background: white; padding: 20px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); border-left: 5px solid #667eea; }
        .stat-box h3 { font-size: 14px; color: #666; margin-bottom: 5px; }
        .stat-box .number { font-size: 28px; font-weight: 700; color: #333; }

        .dashboard-table-wrapper { overflow-x: auto; background: white; border-radius: 15px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1); padding: 20px; }
        .dash-table { width: 100%; border-collapse: collapse; min-width: 1000px; }
        .dash-table th { background: #f8f9fa; padding: 15px; text-align: left; font-weight: 600; color: #444; border-bottom: 2px solid #eee; position: sticky; top: 0; }
        .dash-table td { padding: 12px 15px; border-bottom: 1px solid #f0f0f0; color: #555; vertical-align: middle; }
        .dash-table tr:hover { background-color: #f8faff; }
        
        .count-badge { 
            display: inline-block; padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; 
            cursor: pointer; transition: transform 0.2s; background: #e8eaf6; color: #3949ab; border: 1px solid #c5cae9;
        }
        .count-badge:hover { transform: scale(1.1); background: #667eea; color: white; border-color: #667eea; }
        .count-badge.zero { background: transparent; color: #bbb; border: 1px solid #eee; cursor: default; }
        .count-badge.zero:hover { transform: none; background: transparent; color: #bbb; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div><h1>🛡️ Recon Pipeline</h1><p class="subtitle">Automated Security Scanning</p></div>
            <a href="/logout" class="logout-btn">Logout</a>
        </div>

        <div class="nav-tabs">
            <button class="nav-btn active" onclick="switchTab('scanner')">🚀 Scanner</button>
            <button class="nav-btn" onclick="switchTab('dashboard')">📊 Dashboard</button>
        </div>
       
        <div id="view-scanner" class="dashboard-container active">
            <div class="main-content">
                <div class="card">
                    <h2>Configure Scan</h2>
                    <form id="scanForm" onsubmit="event.preventDefault(); startScanHandler()">
                        
                        <div class="form-group">
                            <label>Target(s)</label>
                            <div class="input-actions">
                                <button type="button" class="view-btn" onclick="saveTargetsFromInput()">💾 Save Input</button>
                                <button type="button" class="view-btn" style="background: #ef5350;" onclick="clearTargets()">🗑️ Clear Input</button>
                            </div>
                            <select id="savedTargetsSelect" class="filter-select" style="width: 100%; margin-bottom: 10px;" onchange="selectSavedTarget()">
                                <option value="">📂 Load Saved Target...</option>
                            </select>
                            <textarea id="targets" name="targets" placeholder="Enter domains, IPs... (one per line)" required></textarea>
                        </div>

                        <div class="form-group" style="background: #e3f2fd; padding: 10px; border-radius: 8px;">
                            <label>🕒 Schedule Start Time (Optional)</label>
                            <input type="datetime-local" id="scheduled_time" name="scheduled_time">
                            <label style="margin-top:10px;">🔁 Frequency (Periodic Scan)</label>
                            <select name="frequency" style="margin-top:5px;">
                                <option value="once">Run Once</option>
                                <option value="daily">Daily</option>
                                <option value="weekly">Weekly</option>
                                <option value="monthly">Monthly</option>
                            </select>
                        </div>
                       
                        <div class="form-group">
                            <label>Tools</label>
                            <div class="checkbox-group">
                                <div class="checkbox-item"><input type="checkbox" name="tools" value="subfinder"><label>Subfinder</label></div>
                                <div class="checkbox-item"><input type="checkbox" name="tools" value="puredns"><label>PureDNS</label></div>
                                <div class="checkbox-item"><input type="checkbox" name="tools" value="dnsx"><label>DNSx</label></div>
                                <div class="checkbox-item"><input type="checkbox" name="tools" value="cut-cdn"><label>Cut-CDN</label></div>
                                <div class="checkbox-item"><input type="checkbox" name="tools" value="nmap"><label>Nmap</label></div>
                                <div class="checkbox-item"><input type="checkbox" name="tools" value="tlsx"><label>TLSx</label></div>
                                <div class="checkbox-item"><input type="checkbox" name="tools" value="httpx"><label>HTTPx</label></div>
                                <div class="checkbox-item"><input type="checkbox" name="tools" value="katana"><label>Katana</label></div>
                                <div class="checkbox-item"><input type="checkbox" name="tools" value="vhost"><label>VHost</label></div>
                                <div class="checkbox-item"><input type="checkbox" name="tools" value="sni"><label>SNI Check</label></div>
                                <div class="checkbox-item"><input type="checkbox" name="tools" value="nuclei"><label>Nuclei</label></div>
                                <div class="checkbox-item"><input type="checkbox" name="tools" value="ffuf"><label>FFUF</label></div>
                                <div class="checkbox-item"><input type="checkbox" name="tools" value="gowitness"><label>Gowitness</label></div>
                            </div>
                        </div>
                        
                        <div class="advanced-config">
                            <div class="advanced-header" onclick="toggleSection('purednsWlistBody', 'purednsWlistArrow')">
                                <span>📚 Wordlist (PureDNS) - Local Files</span>
                                <span id="purednsWlistArrow">▼</span>
                            </div>
                            <div class="advanced-body" id="purednsWlistBody">
                                <div class="checkbox-group" id="purednsWordlistContainer" style="grid-column: 1 / -1;">
                                    <div style="padding:10px; color:#666;">Loading files...</div>
                                </div>
                            </div>
                        </div>

                        <div class="advanced-config">
                            <div class="advanced-header" onclick="toggleSection('ffufWlistBody', 'ffufWlistArrow')">
                                <span>📚 Wordlist (FFUF & VHost) - Local Files</span>
                                <span id="ffufWlistArrow">▼</span>
                            </div>
                            <div class="advanced-body" id="ffufWlistBody">
                                <div class="checkbox-group" id="ffufWordlistContainer" style="grid-column: 1 / -1;">
                                    <div style="padding:10px; color:#666;">Loading files...</div>
                                </div>
                            </div>
                        </div>

                        <div class="advanced-config">
                            <div class="advanced-header" onclick="toggleSection('nucleiBody', 'nucleiArrow')">
                                <span>☢️ Nuclei Categories</span>
                                <span id="nucleiArrow">▼</span>
                            </div>
                            <div class="advanced-body" id="nucleiBody">
                                <div class="checkbox-group" style="grid-column: 1 / -1;">
                                    <div class="checkbox-item"><input type="checkbox" name="nuclei_category" value="cves"><label>CVEs</label></div>
                                    <div class="checkbox-item"><input type="checkbox" name="nuclei_category" value="cnvd"><label>CNVD</label></div>
                                    <div class="checkbox-item"><input type="checkbox" name="nuclei_category" value="vulnerabilities"><label>Vulns</label></div>
                                    <div class="checkbox-item"><input type="checkbox" name="nuclei_category" value="misconfiguration"><label>Misconfig</label></div>
                                    <div class="checkbox-item"><input type="checkbox" name="nuclei_category" value="default-logins"><label>Logins</label></div>
                                    <div class="checkbox-item"><input type="checkbox" name="nuclei_category" value="exposed-panels"><label>Panels</label></div>
                                    <div class="checkbox-item"><input type="checkbox" name="nuclei_category" value="technologies"><label>Tech</label></div>
                                    <div class="checkbox-item"><input type="checkbox" name="nuclei_category" value="exposures"><label>Exposures</label></div>
                                    <div class="checkbox-item"><input type="checkbox" name="nuclei_category" value="takeovers"><label>Takeovers</label></div>
                                    <div class="checkbox-item"><input type="checkbox" name="nuclei_category" value="token-spray"><label>Tokens</label></div>
                                    <div class="checkbox-item"><input type="checkbox" name="nuclei_category" value="network"><label>Network</label></div>
                                    <div class="checkbox-item"><input type="checkbox" name="nuclei_category" value="dns"><label>DNS</label></div>
                                    <div class="checkbox-item"><input type="checkbox" name="nuclei_category" value="iot"><label>IoT</label></div>
                                    <div class="checkbox-item"><input type="checkbox" name="nuclei_category" value="file"><label>File</label></div>
                                    <div class="checkbox-item"><input type="checkbox" name="nuclei_category" value="fuzzing"><label>Fuzzing</label></div>
                                    <div class="checkbox-item"><input type="checkbox" name="nuclei_category" value="miscellaneous"><label>Misc</label></div>
                                </div>
                            </div>
                        </div>

                        <div class="advanced-config">
                            <div class="advanced-header" onclick="toggleSection('nucleiSevBody', 'nucleiSevArrow')">
                                <span>☢️ Nuclei Severity</span>
                                <span id="nucleiSevArrow">▼</span>
                            </div>
                            <div class="advanced-body" id="nucleiSevBody">
                                <div class="checkbox-group" style="grid-column: 1 / -1;">
                                    <div class="checkbox-item"><input type="checkbox" name="nuclei_severity" value="info"><label>Info</label></div>
                                    <div class="checkbox-item"><input type="checkbox" name="nuclei_severity" value="low" checked><label>Low</label></div>
                                    <div class="checkbox-item"><input type="checkbox" name="nuclei_severity" value="medium"><label>Medium</label></div>
                                    <div class="checkbox-item"><input type="checkbox" name="nuclei_severity" value="high" checked><label>High</label></div>
                                    <div class="checkbox-item"><input type="checkbox" name="nuclei_severity" value="critical" checked><label>Critical</label></div>
                                </div>
                            </div>
                        </div>

                        <div class="advanced-config">
                            <div class="advanced-header" onclick="toggleSection('proxyBody', 'proxyArrow')">
                                <span>🌐 Network & Proxy Configuration</span>
                                <span id="proxyArrow">▼</span>
                            </div>
                            <div class="advanced-body" id="proxyBody">
                                <div class="config-item" style="grid-column: 1 / -1;">
                                    <label>Proxy URL (e.g., http://127.0.0.1:8080 or socks5://127.0.0.1:9050)</label>
                                    <input type="text" name="proxy_url" placeholder="Enter proxy URL here...">
                                </div>
                                <div class="config-item" style="grid-column: 1 / -1;">
                                    <label>Enable Proxy for Tools:</label>
                                    <div class="checkbox-group">
                                        <div class="checkbox-item"><input type="checkbox" name="proxy_tools" value="subfinder"><label>Subfinder</label></div>
                                        <div class="checkbox-item"><input type="checkbox" name="proxy_tools" value="httpx"><label>HTTPx</label></div>
                                        <div class="checkbox-item"><input type="checkbox" name="proxy_tools" value="tlsx"><label>TLSx</label></div>
                                        <div class="checkbox-item"><input type="checkbox" name="proxy_tools" value="katana"><label>Katana</label></div>
                                        <div class="checkbox-item"><input type="checkbox" name="proxy_tools" value="nuclei"><label>Nuclei</label></div>
                                        <div class="checkbox-item"><input type="checkbox" name="proxy_tools" value="ffuf"><label>FFUF (Dir/VHost/SNI)</label></div>
                                        <div class="checkbox-item"><input type="checkbox" name="proxy_tools" value="nmap"><label>Nmap</label></div>
                                        <div class="checkbox-item"><input type="checkbox" name="proxy_tools" value="gowitness"><label>Gowitness</label></div>
                                    </div>
                                    <small style="color: red;">Note: DNS tools (PureDNS, DNSx) do not support standard HTTP/Socks proxies.</small>
                                </div>
                            </div>
                        </div>

                        <div class="advanced-config">
                            <div class="advanced-header" onclick="toggleSection('advancedBody', 'advArrow')">
                                <span>⚙️ Advanced Tool Options (Args)</span>
                                <span id="advArrow">▼</span>
                            </div>
                            <div class="advanced-body" id="advancedBody">
                                <div class="config-item"><label>Subfinder Args</label><input type="text" name="args_subfinder" value="-rl 1 -all"></div>
                                <div class="config-item"><label>HTTPx Args</label><input type="text" name="args_httpx" value="-probe -tech-detect"></div>
                                <div class="config-item"><label>Katana Args</label><input type="text" name="args_katana" value="-d 3 -timeout 30"></div>
                                <div class="config-item"><label>Nmap Args</label><input type="text" name="args_nmap" value="-sV -T4 -Pn --open"></div>
                                <div class="config-item"><label>VHost FFUF Args</label><input type="text" name="args_vhost" value="-ac -t 10 -rate 5 -H 'User-Agent: Mozilla/5.0'"></div>
                                <div class="config-item"><label>Dir FFUF Args</label><input type="text" name="args_ffuf" value="-ac -t 10 -rate 5"></div>
                                <div class="config-item"><label>Nuclei Args</label><input type="text" name="args_nuclei" value="-rl 150 -c 25 -timeout 10"></div>
                                <div class="config-item"><label>Gowitness Args</label><input type="text" name="args_gowitness" value="--disable-logging"></div>
                            </div>
                        </div>

                        <button type="submit" class="btn" id="startBtn" style="margin-top: 20px;">Start Scan</button>
                    </form>
                </div>
               
                <div class="card">
                    <h2>Pipeline Status</h2>
                    <div id="statusMessage" class="alert alert-info" style="display: none;"></div>
                    <div class="pipeline-stages" id="pipelineStages">
                         <div class="stage" data-stage="subfinder"><div class="stage-header"><span class="stage-name">1. Subfinder</span><span class="stage-status">Pending</span></div><div class="stage-output"></div><div class="progress-wrapper"><div class="progress-fill" style="width:0%"></div></div></div>
                        <div class="stage" data-stage="puredns"><div class="stage-header"><span class="stage-name">2. PureDNS</span><span class="stage-status">Pending</span></div><div class="stage-output"></div><div class="progress-wrapper"><div class="progress-fill" style="width:0%"></div></div></div>
                        <div class="stage" data-stage="dnsx"><div class="stage-header"><span class="stage-name">3. DNSx</span><span class="stage-status">Pending</span></div><div class="stage-output"></div><div class="progress-wrapper"><div class="progress-fill" style="width:0%"></div></div></div>
                        <div class="stage" data-stage="cut-cdn"><div class="stage-header"><span class="stage-name">4. Cut-CDN</span><span class="stage-status">Pending</span></div><div class="stage-output"></div><div class="progress-wrapper"><div class="progress-fill" style="width:0%"></div></div></div>
                        <div class="stage" data-stage="nmap"><div class="stage-header"><span class="stage-name">5. Nmap</span><span class="stage-status">Pending</span></div><div class="stage-output"></div><div class="progress-wrapper"><div class="progress-fill" style="width:0%"></div></div></div>
                        <div class="stage" data-stage="tlsx"><div class="stage-header"><span class="stage-name">6. TLSx</span><span class="stage-status">Pending</span></div><div class="stage-output"></div><div class="progress-wrapper"><div class="progress-fill" style="width:0%"></div></div></div>
                        <div class="stage" data-stage="httpx"><div class="stage-header"><span class="stage-name">7. HTTPx</span><span class="stage-status">Pending</span></div><div class="stage-output"></div><div class="progress-wrapper"><div class="progress-fill" style="width:0%"></div></div></div>
                        <div class="stage" data-stage="katana"><div class="stage-header"><span class="stage-name">8. Katana</span><span class="stage-status">Pending</span></div><div class="stage-output"></div><div class="progress-wrapper"><div class="progress-fill" style="width:0%"></div></div></div>
                        <div class="stage" data-stage="vhost"><div class="stage-header"><span class="stage-name">9. VHost Scan</span><span class="stage-status">Pending</span></div><div class="stage-output"></div><div class="progress-wrapper"><div class="progress-fill" style="width:0%"></div></div></div>
                        <div class="stage" data-stage="sni"><div class="stage-header"><span class="stage-name">10. SNI Check</span><span class="stage-status">Pending</span></div><div class="stage-output"></div><div class="progress-wrapper"><div class="progress-fill" style="width:0%"></div></div></div>
                        <div class="stage" data-stage="nuclei"><div class="stage-header"><span class="stage-name">11. Nuclei</span><span class="stage-status">Pending</span></div><div class="stage-output"></div><div class="progress-wrapper"><div class="progress-fill" style="width:0%"></div></div></div>
                        <div class="stage" data-stage="ffuf"><div class="stage-header"><span class="stage-name">12. FFUF (Dir)</span><span class="stage-status">Pending</span></div><div class="stage-output"></div><div class="progress-wrapper"><div class="progress-fill" style="width:0%"></div></div></div>
                        <div class="stage" data-stage="gowitness"><div class="stage-header"><span class="stage-name">13. Gowitness</span><span class="stage-status">Pending</span></div><div class="stage-output"></div><div class="progress-wrapper"><div class="progress-fill" style="width:0%"></div></div></div>
                    </div>
                </div>
            </div>
           
            <div class="card results-panel" id="resultsPanel" style="display: none;">
                <h2>Scan Results</h2>
                <div class="results-grid" id="resultsGrid"></div>
                <div class="download-section" id="downloadSection"></div>
                <div style="margin-top: 20px; border-top: 1px solid #ddd; padding-top: 10px;">
                    <h3>📂 Raw Output Files</h3>
                    <div id="fileList" class="file-list"></div>
                </div>
            </div>

            <div class="card" style="margin-top: 20px;">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                    <h2>📜 Scan History</h2>
                    <div style="display: flex; gap: 10px; align-items: center;">
                        <input type="text" id="historyTargetFilter" class="filter-input" placeholder="Filter by target..." oninput="loadHistory(1)">
                        <select id="historyFilter" class="filter-select" onchange="loadHistory(1)">
                            <option value="">All Scans</option>
                            <option value="completed">Completed Only</option>
                            <option value="running">Running Only</option>
                            <option value="scheduled">Scheduled</option>
                            <option value="stopped">Stopped</option>
                            <option value="error">Failed/Interrupted</option>
                        </select>
                        <select id="rowsPerPage" class="filter-select" style="min-width: 80px;" onchange="loadHistory(1)">
                            <option value="10">10 / page</option>
                            <option value="20">20 / page</option>
                        </select>
                    </div>
                </div>
                <div id="historyList">
                    <table class="history-table">
                        <thead><tr><th>ID</th><th>Target</th><th>Date</th><th>Status</th><th>Action</th></tr></thead>
                        <tbody id="historyTableBody"><tr><td colspan="5">Loading...</td></tr></tbody>
                    </table>
                    <div class="pagination-controls">
                        <button id="prevPageBtn" class="view-btn" onclick="changePage(-1)" disabled>Previous</button>
                        <span id="pageIndicator" style="font-size: 14px; color: #666;">Page 1</span>
                        <button id="nextPageBtn" class="view-btn" onclick="changePage(1)" disabled>Next</button>
                    </div>
                </div>
            </div>
        </div>
        
        <div id="view-dashboard" class="dashboard-container">
            <div class="card" style="margin-bottom: 20px; padding: 20px;">
                <h2 style="margin-bottom: 15px;">Dashboard Filters</h2>
                <div style="display: flex; gap: 15px; align-items: center; flex-wrap: wrap;">
                    <input type="text" id="dashboardTargetFilter" placeholder="Filter by target..." style="flex-grow: 1; min-width: 250px;">
                    <div style="display: flex; gap: 5px; align-items: center; background: #f0f4f8; padding: 5px; border-radius: 8px;">
                        <input type="date" id="dashboardStartDate" title="Start Date">
                        <span style="color: #666;">to</span>
                        <input type="date" id="dashboardEndDate" title="End Date">
                    </div>
                    <button class="view-btn" onclick="loadDashboardData(1)" style="padding: 10px 20px;">🔍 Apply</button>
                </div>
            </div>

            <div class="stats-grid">
                <div class="stat-box"><h3>Total Scans</h3><div class="number" id="dashTotalScans">0</div></div>
                <div class="stat-box"><h3>Completed</h3><div class="number" id="dashCompleted">0</div></div>
                <div class="stat-box"><h3>Total Subdomains</h3><div class="number" id="dashSubdomains">0</div></div>
                <div class="stat-box"><h3>Total Vulnerabilities</h3><div class="number" id="dashVulns">0</div></div>
            </div>

            <div class="card dashboard-table-wrapper">
                <h2 style="margin-bottom: 15px;">Scan Results Summary</h2>
                <table class="dash-table">
                    <thead>
                        <tr>
                            <th>Date</th><th>Target</th><th>Status</th>
                            <th>Subfinder</th><th>PureDNS</th><th>DNSx</th><th>TLSx</th>
                            <th>HTTPx</th><th>Katana</th><th>Nuclei</th><th>FFUF</th><th>SNI</th>
                        </tr>
                    </thead>
                    <tbody id="dashboardTableBody">
                        <tr><td colspan="12" style="text-align:center;">Loading dashboard data...</td></tr>
                    </tbody>
                </table>
                <div class="pagination-controls">
                    <button id="dashPrevPageBtn" class="view-btn" onclick="changeDashboardPage(-1)" disabled>Previous</button>
                    <span id="dashPageIndicator" style="font-size: 14px; color: #666;">Page 1</span>
                    <button id="dashNextPageBtn" class="view-btn" onclick="changeDashboardPage(1)" disabled>Next</button>
                </div>
            </div>
        </div>
    </div>

    <div id="fileModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal()">&times;</span>
            <h3 id="modalTitle">File Content</h3>
            <pre><code id="fileContent"></code></pre>
        </div>
    </div>
   
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
    <script>
        let socket = null;
        try { socket = io(); } catch(e) { console.error("Socket error:", e); }
        let currentScanId = null;
        let pollInterval = null;
        let historyCurrentPage = 1;
        let dashboardCurrentPage = 1;

        function toggleSection(id, arrowId) {
            const body = document.getElementById(id);
            const arrow = document.getElementById(arrowId);
            if (body.classList.contains('show')) {
                body.classList.remove('show');
                arrow.textContent = '▼';
                body.style.display = 'none';
            } else {
                body.classList.add('show');
                arrow.textContent = '▲';
                body.style.display = 'grid';
            }
        }
        
        async function loadTargets() {
            try {
                const res = await fetch('/api/targets');
                const targets = await res.json();
                const select = document.getElementById('savedTargetsSelect');
                while (select.options.length > 1) { select.remove(1); }
                targets.forEach(t => {
                    const option = document.createElement('option');
                    option.value = t;
                    option.textContent = t;
                    select.appendChild(option);
                });
            } catch(e) { console.error(e); }
        }

        async function loadLocalWordlists() {
            try {
                const res = await fetch('/api/local_wordlists');
                const files = await res.json();
                
                // Maps: Container ID -> Input Name
                const targets = {
                    'purednsWordlistContainer': 'wordlist_puredns_select',
                    'ffufWordlistContainer': 'wordlist_ffuf_select'
                };

                for (const [containerId, inputName] of Object.entries(targets)) {
                    const container = document.getElementById(containerId);
                    if (container) {
                        container.innerHTML = '';
                        if (!files || files.length === 0) {
                            container.innerHTML = '<div style="padding:10px; color:#666; font-style:italic;">No .txt files found in root directory.</div>';
                        } else {
                            files.forEach(f => {
                                // Using Radio buttons to enforce single file selection as required by tool logic
                                const item = document.createElement('div');
                                item.className = 'checkbox-item';
                                item.innerHTML = `<input type="radio" name="${inputName}" value="${f}"><label>${f}</label>`;
                                container.appendChild(item);
                            });
                        }
                    }
                }
            } catch(e) { console.error("Error loading wordlists:", e); }
        }

        function selectSavedTarget() {
            const select = document.getElementById('savedTargetsSelect');
            const target = select.value;
            if (!target) return;
            const area = document.getElementById('targets');
            const currentVal = area.value.trim();
            area.value = currentVal ? currentVal + '\\n' + target : target;
            select.selectedIndex = 0;
        }

        async function saveTargetsFromInput() {
            const area = document.getElementById('targets');
            const lines = area.value.split('\\n').map(l => l.trim()).filter(l => l);
            if(lines.length === 0) { alert("Please enter targets first."); return; }
            for (const line of lines) {
                await fetch('/api/targets', {
                    method: 'POST', 
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target: line})
                });
            }
            loadTargets();
        }

        function clearTargets() {
            if(confirm("Clear current input area?")) { document.getElementById('targets').value = ''; }
        }

        document.addEventListener('DOMContentLoaded', () => {
            loadHistory(1);
            loadTargets(); 
            loadLocalWordlists();
        });

        async function startScanHandler() {
            const form = document.getElementById('scanForm');
            const formData = new FormData(form);
            resetPipeline();
            const btn = document.getElementById('startBtn');
            btn.disabled = true;
            btn.innerHTML = 'Processing...';
            try {
                const response = await fetch('/start_scan', { method: 'POST', body: formData });
                const data = await response.json();
                if (data.scan_id) {
                    currentScanId = data.scan_id;
                    if(data.status === 'scheduled') {
                        showStatus('Scan scheduled successfully', 'success');
                        resetButton();
                    } else {
                        if(socket) socket.emit('join', currentScanId);
                        showStatus('Scan started successfully!', 'success');
                        startPolling();
                    }
                    loadHistory(1); 
                } else {
                    showStatus('Error: ' + (data.error || 'Unknown error'), 'error');
                    resetButton();
                }
            } catch (error) {
                showStatus('Connection Error: ' + error.message, 'error');
                resetButton();
            }
        }
       
        if(socket) {
            socket.on('stage_update', (data) => {
                const { stage, status, output, progress } = data;
                const stageEl = document.querySelector(`[data-stage="${stage}"]`);
                if (stageEl) {
                    stageEl.className = 'stage ' + status;
                    stageEl.querySelector('.stage-status').textContent = status.toUpperCase();
                    if (output) stageEl.querySelector('.stage-output').textContent = output;
                    if (progress !== undefined) {
                        const fill = stageEl.querySelector('.progress-fill');
                        if(fill) fill.style.width = progress + '%';
                    }
                }
            });
        }

        async function loadHistory(page = 1) {
            historyCurrentPage = page;
            try {
                const statusFilter = document.getElementById('historyFilter').value;
                const targetFilter = document.getElementById('historyTargetFilter').value;
                const perPage = document.getElementById('rowsPerPage').value; 
                
                const params = new URLSearchParams({ page: page, per_page: perPage });
                if (statusFilter) params.append('status', statusFilter);
                if (targetFilter) params.append('target', targetFilter);
                
                const url = `/api/history?${params.toString()}`;
                const res = await fetch(url);
                const data = await res.json(); 
                const tbody = document.getElementById('historyTableBody');
                tbody.innerHTML = '';
                
                if (!data.scans || data.scans.length === 0) {
                     tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">No scans found.</td></tr>';
                } else {
                    data.scans.forEach(scan => {
                        const row = document.createElement('tr');
                        const targetDisplay = scan.targets.length > 30 ? scan.targets.substring(0, 30) + '...' : scan.targets;
                        let actions = `<button class="view-btn" onclick="viewScan('${scan.scan_id}')">View</button>`;
                        if (scan.status === 'running') {
                             actions += `<button class="stop-btn" onclick="stopScan('${scan.scan_id}')">Stop</button>`;
                        } else if (scan.status === 'stopped' || scan.status === 'interrupted') {
                             actions += `<button class="resume-btn" onclick="resumeScan('${scan.scan_id}')">Resume</button>`;
                        }
                        actions += `<button class="delete-btn" onclick="deleteScan('${scan.scan_id}')">Delete</button>`;
                        row.innerHTML = `<td>${scan.scan_id}</td><td title="${scan.targets}">${targetDisplay}</td><td>${new Date(scan.created_at).toLocaleString()}</td><td style="color:${getStatusColor(scan.status)}">${scan.status.toUpperCase()}</td><td>${actions}</td>`;
                        tbody.appendChild(row);
                    });
                }
                const totalPages = data.total_pages || 1;
                document.getElementById('pageIndicator').textContent = `Page ${data.page} of ${totalPages}`;
                document.getElementById('prevPageBtn').disabled = (data.page <= 1);
                document.getElementById('nextPageBtn').disabled = (data.page >= totalPages);

            } catch (e) { console.error(e); }
        }
        
        function changePage(delta) { loadHistory(historyCurrentPage + delta); }
        
        function getStatusColor(status) {
            if(status === 'completed') return '#4caf50';
            if(status === 'running') return '#ff9800';
            if(status === 'scheduled') return '#2196f3';
            if(status === 'stopped') return '#9e9e9e';
            return '#f44336';
        }

        function viewScan(id) {
            switchTab('scanner', false); // Force switch back, don't trigger dashboard load
            currentScanId = id;
            if(socket) socket.emit('join', id);
            resetPipeline();
            fetch(`/scan_status/${id}`).then(r => r.json()).then(data => {
                if (data.status) {
                    updatePipelineUI(data);
                    if (data.results) displayResults(data.results);
                    loadFiles(id);
                    if (['completed','error','interrupted','stopped'].includes(data.status)) {
                        resetButton();
                    }
                }
            });
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }

        async function deleteScan(id) {
            if(!confirm("Delete scan?")) return;
            await fetch(`/api/delete_scan/${id}`, { method: 'DELETE' });
            loadHistory(historyCurrentPage);
        }
        
        async function stopScan(id) {
            if(!confirm("Are you sure you want to stop this scan?")) return;
            await fetch(`/api/stop_scan/${id}`, { method: 'POST' });
            loadHistory(historyCurrentPage);
            if(currentScanId === id) showStatus("Scan stopped by user.", "error");
        }
        
        async function resumeScan(id) {
            if(!confirm("Resume this scan from where it left off?")) return;
            await fetch(`/api/resume_scan/${id}`, { method: 'POST' });
            viewScan(id);
            loadHistory(historyCurrentPage);
        }

        async function loadFiles(id) {
            const listDiv = document.getElementById('fileList');
            listDiv.innerHTML = 'Loading files...';
            try {
                const res = await fetch(`/api/scan_files/${id}`);
                const files = await res.json();
                listDiv.innerHTML = '';
                files.forEach(f => {
                    const tag = document.createElement('span');
                    tag.className = 'file-tag';
                    tag.textContent = f;
                    tag.onclick = () => viewFileContent(id, f);
                    listDiv.appendChild(tag);
                });
            } catch(e) { listDiv.innerHTML = ''; }
        }

        // --- MODAL AND FILE VIEWING LOGIC ---
        function updateModalContent(text, language = 'plaintext') {
            const contentEl = document.getElementById('fileContent');
            contentEl.textContent = text;
            contentEl.className = `language-${language}`;
            if (window.hljs) {
                hljs.highlightElement(contentEl);
            }
        }
        
        async function viewFileContent(id, filename) {
            const modal = document.getElementById('fileModal');
            document.getElementById('modalTitle').textContent = filename;
            updateModalContent("Loading...");
            modal.style.display = "block";
            try {
                const res = await fetch(`/api/view_file/${id}/${filename}`);
                const text = await res.text();
                const lang = (filename.endsWith('.json') || filename.endsWith('.jsonl')) ? 'json' : 'plaintext';
                updateModalContent(text, lang);
            } catch (e) {
                updateModalContent("Error loading file content.");
            }
        }

        function closeModal() { 
            document.getElementById('fileModal').style.display = "none"; 
        }
       
        function resetPipeline() {
            document.querySelectorAll('.stage').forEach(stage => {
                stage.className = 'stage';
                stage.querySelector('.stage-status').textContent = 'Pending';
                stage.querySelector('.stage-output').textContent = '';
                const fill = stage.querySelector('.progress-fill');
                if(fill) fill.style.width = '0%';
            });
            document.getElementById('resultsPanel').style.display = 'none';
            document.getElementById('fileList').innerHTML = '';
        }
       
        function resetButton() {
            const btn = document.getElementById('startBtn');
            btn.disabled = false;
            btn.textContent = 'Start Scan';
        }
       
        function showStatus(message, type) {
            const statusEl = document.getElementById('statusMessage');
            statusEl.className = `alert alert-${type}`;
            statusEl.textContent = message;
            statusEl.style.display = 'block';
        }
       
        function startPolling() {
            if (pollInterval) clearInterval(pollInterval);
            pollInterval = setInterval(checkStatus, 3000);
        }
       
        async function checkStatus() {
            if (!currentScanId) return;
            try {
                const response = await fetch(`/scan_status/${currentScanId}`);
                const data = await response.json();
                updatePipelineUI(data);
                if (['completed', 'error', 'interrupted', 'stopped'].includes(data.status)) {
                    clearInterval(pollInterval);
                    pollInterval = null;
                    resetButton();
                    if (data.status === 'completed') {
                        showStatus('Scan completed!', 'success');
                        displayResults(data.results);
                        loadFiles(currentScanId);
                    }
                    loadHistory(historyCurrentPage); 
                }
            } catch (error) { console.error(error); }
        }

        function updatePipelineUI(data) {
            if (!data.stages) return;
            Object.keys(data.stages).forEach(stageName => {
                const stageData = data.stages[stageName];
                const stageEl = document.querySelector(`[data-stage="${stageName}"]`);
                if (stageEl) {
                    stageEl.className = 'stage ' + stageData.status;
                    stageEl.querySelector('.stage-status').textContent = stageData.status.toUpperCase();
                    if (stageData.output) stageEl.querySelector('.stage-output').textContent = stageData.output;
                    if (stageData.status === 'completed') stageEl.querySelector('.progress-fill').style.width = '100%';
                }
            });
        }
       
        function displayResults(results) {
            const resultsGrid = document.getElementById('resultsGrid');
            const downloadSection = document.getElementById('downloadSection');
            resultsGrid.innerHTML = '';
            if (results) {
                Object.keys(results).forEach(key => {
                    const card = document.createElement('div');
                    card.className = 'result-card';
                    card.innerHTML = `<div class="result-number">${results[key]}</div><div class="result-label">${key.replace(/_/g, ' ').toUpperCase()}</div>`;
                    resultsGrid.appendChild(card);
                });
                
                downloadSection.innerHTML = `<h3>Download Results</h3>
                <div class="download-buttons">
                    <button class="btn download-btn" onclick="window.location.href='/download/${currentScanId}'">📥 Download ZIP</button>
                    <button class="btn download-btn" style="background: #2196f3;" onclick="window.location.href='/export_csv/${currentScanId}'">📊 Export CSV</button>
                </div>`;
                
                document.getElementById('resultsPanel').style.display = 'block';
            }
        }

        // --- DASHBOARD LOGIC ---

        function switchTab(tabName, doLoad = true) {
            document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelector(`.nav-btn[onclick="switchTab('${tabName}')"]`).classList.add('active');
            
            document.getElementById('view-scanner').classList.remove('active');
            document.getElementById('view-dashboard').classList.remove('active');
            document.getElementById(`view-${tabName}`).classList.add('active');
            
            if (tabName === 'dashboard' && doLoad) {
                loadDashboardData(1);
            }
        }

        async function loadDashboardData(page = 1) {
            dashboardCurrentPage = page;
            try {
                const targetFilter = document.getElementById('dashboardTargetFilter').value;
                const startDate = document.getElementById('dashboardStartDate').value;
                const endDate = document.getElementById('dashboardEndDate').value;

                const params = new URLSearchParams({ page: page, per_page: 10 }); // 10 rows per page
                if (targetFilter) params.append('target', targetFilter);
                if (startDate) params.append('start_date', new Date(startDate).toISOString());
                if (endDate) {
                    let end = new Date(endDate);
                    end.setHours(23, 59, 59, 999);
                    params.append('end_date', end.toISOString());
                }

                const res = await fetch(`/api/history?${params.toString()}`);
                const data = await res.json();
                
                // Only update stats on the first page load to get total counts
                if (page === 1) {
                    const statsRes = await fetch(`/api/history?${params.toString()}&per_page=9999`);
                    const statsData = await statsRes.json();
                    renderDashboardStats(statsData.scans);
                }
                
                renderDashboardTable(data.scans, data.page, data.total_pages);
            } catch(e) { console.error("Dashboard Load Error", e); }
        }
        
        function changeDashboardPage(delta) {
            loadDashboardData(dashboardCurrentPage + delta);
        }

        function renderDashboardStats(scans) {
            document.getElementById('dashTotalScans').textContent = scans.length;
            document.getElementById('dashCompleted').textContent = scans.filter(s => s.status === 'completed').length;
            
            let totalVulns = 0;
            let totalSubs = 0;
            scans.forEach(s => {
                if (s.results) {
                    totalVulns += (s.results.nuclei || 0);
                    totalSubs += (s.results.subfinder || 0) + (s.results.puredns || 0);
                }
            });
            document.getElementById('dashVulns').textContent = totalVulns;
            document.getElementById('dashSubdomains').textContent = totalSubs;
        }

        function renderDashboardTable(scans, page, totalPages) {
            const tbody = document.getElementById('dashboardTableBody');
            tbody.innerHTML = '';
            
            if (scans.length === 0) {
                tbody.innerHTML = '<tr><td colspan="12" style="text-align:center;">No data available for this filter/page.</td></tr>';
            } else {
                scans.forEach(s => {
                    const row = document.createElement('tr');
                    const r = s.results || {};
                    const targetShort = s.targets.length > 25 ? s.targets.substring(0,25)+'...' : s.targets;
                    
                    const createCell = (tool, defaultFile) => {
                        const count = r[tool] || 0;
                        const className = count > 0 ? 'count-badge' : 'count-badge zero';
                        const clickAttr = count > 0 ? `onclick="openToolFile('${s.scan_id}', '${defaultFile}', '${tool}')"` : '';
                        return `<td><span class="${className}" ${clickAttr}>${count}</span></td>`;
                    };

                    row.innerHTML = `
                        <td>${new Date(s.created_at).toLocaleDateString()}</td>
                        <td title="${s.targets}" style="font-weight:500;">${targetShort}</td>
                        <td><span style="color:${getStatusColor(s.status)}">${s.status.toUpperCase()}</span></td>
                        ${createCell('subfinder', 'subfinder.txt')}
                        ${createCell('puredns', 'puredns_all.txt')}
                        ${createCell('dnsx', 'dnsx.txt')}
                        ${createCell('tlsx', 'tlsx.txt')}
                        ${createCell('httpx', 'httpx.txt')}
                        ${createCell('katana', 'katana.txt')}
                        ${createCell('nuclei', 'nuclei.txt')}
                        ${createCell('ffuf', 'ffuf_dir.txt')}
                        ${createCell('sni', 'sni.txt')}
                    `;
                    tbody.appendChild(row);
                });
            }
            
            document.getElementById('dashPageIndicator').textContent = `Page ${page} of ${totalPages}`;
            document.getElementById('dashPrevPageBtn').disabled = (page <= 1);
            document.getElementById('dashNextPageBtn').disabled = (page >= totalPages);
        }
        
        async function openToolFile(scanId, defaultFile, toolName) {
            const modal = document.getElementById('fileModal');
            document.getElementById('modalTitle').textContent = `${toolName.toUpperCase()} Clean Result`;
            updateModalContent("Loading...");
            modal.style.display = "block";

            let finalFilename = defaultFile;

            try {
                let res = await fetch(`/api/view_file/${scanId}/${defaultFile}`);
                
                if (!res.ok || (await res.clone().text()).includes('Error')) {
                    updateModalContent("Default clean file not found. Searching available files...");
                    const listRes = await fetch(`/api/scan_files/${scanId}`);
                    const files = await listRes.json();
                    
                    let match = files.find(f => f.includes(toolName) && f.endsWith('.txt'));
                    if (!match) match = files.find(f => f.includes(toolName));

                    if (match) {
                        res = await fetch(`/api/view_file/${scanId}/${match}`);
                        finalFilename = match;
                    } else {
                        updateModalContent("No clean log file found for this tool.");
                        return;
                    }
                }
                
                const text = await res.text();
                const lang = (finalFilename.endsWith('.json') || finalFilename.endsWith('.jsonl')) ? 'json' : 'plaintext';
                updateModalContent(text, lang);

            } catch(e) {
                updateModalContent("Error loading file.");
            }
        }
    </script>
</body>
</html>
"""

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; justify-content: center; align-items: center; margin: 0; }
        .login-box { background: white; padding: 40px; border-radius: 10px; width: 350px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); }
        input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #667eea; color: white; border: none; border-radius: 5px; cursor: pointer; margin-top: 10px; font-size: 16px; }
        h2 { text-align: center; color: #333; margin-bottom: 20px; }
        .error { color: red; text-align: center; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Recon Pipeline</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        {% if error %}<p class="error">{{ error }}</p>{% endif %}
    </div>
</body>
</html>
"""

# --- Logic Classes ---

def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'): 
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

class ScanRunner:
    def __init__(self, scan_id: str, targets: str, selected_tools: List[str], 
                 nuclei_templates_path: Optional[str] = None, puredns_wordlist_path: Optional[str] = None, 
                 ffuf_wordlist_path: Optional[str] = None, nuclei_categories: List[str] = None, 
                 nuclei_severities: List[str] = None, tool_args: Dict[str, str] = None, 
                 proxy_config: Dict[str, Any] = None, resume_mode: bool = False):
        
        self.scan_id = scan_id
        # Sanitize targets immediately
        self.targets = "\n".join([t.strip() for t in targets.split("\n") if t.strip() and len(t.strip()) < 255])
        self.selected_tools = selected_tools
        self.output_dir = Path(f'scans/{scan_id}')
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.nuclei_templates_path = nuclei_templates_path
        self.puredns_wordlist_path = puredns_wordlist_path
        self.ffuf_wordlist_path = ffuf_wordlist_path
        self.nuclei_categories = nuclei_categories or []
        self.nuclei_severities = nuclei_severities or []
        self.tool_args = tool_args or {}
        self.proxy_config = proxy_config or {} 
        self.resume_mode = resume_mode
        
        # Load existing status if resuming, else init new 
        if resume_mode:
            try:
                existing = db.scans.find_one({'scan_id': scan_id})
                self.status = existing if existing else {}
                self.status['status'] = 'running'
                if 'results' not in self.status: 
                    self.status['results'] = {}
            except Exception as e:
                logger.error(f"Error fetching existing scan status for {scan_id}: {e}")
                self.status = {'status': 'error', 'results': {}}
        else:
            self.status = {
                'scan_id': scan_id, 'targets': self.targets, 'status': 'running',
                'stages': {}, 'results': {}, 'created_at': datetime.now().isoformat()
            }

        self.timeout = None  # Max 1 hour per tool default
        self.domain_ip_map = {} 
        self.safe_ips = set()
        self.current_process = None 
        self.stopped = False
    
    def stop(self):
        """Stops the current scan execution with proper process reaping."""
        self.stopped = True
        self.status['status'] = 'stopped'
        if self.current_process:
            try:
                self.current_process.terminate()
                self.current_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.warning(f"Process {self.current_process.pid} did not terminate, forcing kill.")
                self.current_process.kill()
            except Exception as e: 
                logger.error(f"Error stopping process: {e}")
                
        try:
            db.scans.update_one({'scan_id': self.scan_id}, {'$set': {'status': 'stopped'}})
        except Exception as e:
            logger.error(f"Failed to update db status to stopped for {self.scan_id}: {e}")
            
        self.emit_stage_update('pipeline', 'stopped', 'Scan stopped by user.')
        send_telegram_alert(f"🛑 Scan Stopped by User\nTarget: {self.targets[:50]}...")

    def emit_stage_update(self, stage: str, status: str, output: str = '', progress: Optional[int] = None):
        data = {'stage': stage, 'status': status, 'output': output}
        if progress is not None: 
            data['progress'] = progress
            
        try:
            socketio.emit('stage_update', data, room=self.scan_id)
            update = {f'stages.{stage}': {'status': status, 'output': output}, 'status': 'running'}
            db.scans.update_one({'scan_id': self.scan_id}, {'$set': update})
        except Exception as e:
            logger.error(f"Failed emitting stage update for {stage} in {self.scan_id}: {e}")
        
    def update_results(self, tool: str, count: int):
        """Explicitly updates the results count for a tool in local status and MongoDB."""
        self.status['results'][tool] = count
        try:
            db.scans.update_one({'scan_id': self.scan_id}, {'$set': {f'results.{tool}': count}})
        except Exception as e:
            logger.error(f"Failed to update results count for {tool} in {self.scan_id}: {e}")

    def run_command(self, cmd: List[str], input_data: Optional[str] = None, output_file: Optional[str] = None) -> Tuple[str, bool]:
        if self.stopped: 
            return "Scan stopped", True
        
        # Sanitize arguments basic check (ensure list of strings)
        cmd = [str(c) for c in cmd]
        cmd[0] = get_tool_path(cmd[0])
        
        logger.info(f"[{self.scan_id}] Running: {' '.join(shlex.quote(c) for c in cmd)}")
        try:
            stdin = subprocess.PIPE if input_data else None
            stdout = subprocess.PIPE if not output_file else open(output_file, 'w', encoding='utf-8')
            
            self.current_process = subprocess.Popen(
                cmd, stdin=stdin, stdout=stdout, stderr=subprocess.PIPE, 
                text=True, encoding='utf-8', errors='ignore'
            )
            
            stdout_data, stderr_data = self.current_process.communicate(input=input_data, timeout=self.timeout)
            
            if output_file: 
                stdout.close()
                
            return_code = self.current_process.returncode
            self.current_process = None
            
            if self.stopped: 
                return "Scan stopped", True
                
            if return_code != 0: 
                # Some tools exit non-zero on legitimate findings (like Nuclei)
                # But we still log it for observability.
                logger.warning(f"Command exited with code {return_code}: {' '.join(cmd)}\nStderr: {stderr_data}")
                return f"Process finished with code {return_code}. {stderr_data[-200:] if stderr_data else ''}", False
                
            return stdout_data, False
            
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {self.timeout}s: {' '.join(cmd)}")
            if self.current_process:
                self.current_process.kill()
            return "Error: Command timed out", True
        except Exception as e: 
            logger.error(f"Exception running command: {' '.join(cmd)}\nError: {e}", exc_info=True)
            return str(e), True

    def update_stage(self, stage: str, status: str, output: str = '', progress: Optional[int] = None):
        self.status['stages'][stage] = {'status': status, 'output': output}
        self.emit_stage_update(stage, status, output, progress)
        
    def format_and_send_telegram(self, tool: str, file_path: Path, caption: str):
        if not file_path.exists() or os.path.getsize(file_path) == 0: 
            return
        
        clean_file = file_path.with_suffix('.txt')
        if clean_file.exists() and clean_file.resolve() != file_path.resolve():
            send_telegram_document(str(clean_file), caption=caption)
            return

        if os.path.getsize(file_path) > 10 * 1024 * 1024:
            send_telegram_document(str(file_path), caption=caption + " (Large Raw File)")
            return
            
        if tool == 'nuclei' and file_path.suffix in ['.json', '.jsonl']:
            logger.info(f"Skipping raw nuclei JSON telegram send for {file_path}")
            return

        send_telegram_document(str(file_path), caption=caption)

    def generate_clean_output(self, tool: str, source_file: Path) -> Optional[Path]:
        """Generates a clean .txt file from the raw JSON/XML output safely."""
        if not source_file.exists(): 
            return None
        
        clean_file = source_file.with_suffix('.txt')
        if clean_file.resolve() == source_file.resolve(): 
            return source_file

        try:
            if tool not in ['nmap', 'ffuf', 'vhost', 'sni']:
                with open(source_file, 'r', encoding='utf-8', errors='ignore') as f_in, \
                     open(clean_file, 'w', encoding='utf-8') as f_out:
                    for line in f_in:
                        if not line.strip(): 
                            continue
                        try:
                            entry = json.loads(line)
                            out_line = ""
                            if tool == 'subfinder': 
                                out_line = entry.get('host', '')
                            elif tool == 'dnsx': 
                                ips = entry.get('a', [])
                                out_line = f"{entry.get('host', '')} : {', '.join(ips)}" if ips else entry.get('host', '')
                            elif tool == 'tlsx': 
                                out_line = f"{entry.get('host', '')} : {entry.get('ip', '')}"
                            elif tool == 'httpx': 
                                out_line = entry.get('url', '') 
                            elif tool == 'katana': 
                                out_line = entry.get('request', {}).get('endpoint') or entry.get('url', '')
                            elif tool == 'nuclei':
                                info = entry.get('info', {})
                                sev = info.get('severity', 'none').upper()
                                name = info.get('name', 'N/A')
                                matched = entry.get('matched-at', '')
                                out_line = f"[{sev}] {name} @ {matched}"
                            
                            if out_line: 
                                f_out.write(out_line + '\n')
                        except json.JSONDecodeError:
                            pass
                return clean_file
            
            clean_lines = []
            if tool == 'nmap':
                try:
                    tree = ET.parse(source_file)
                    root = tree.getroot()
                    for host in root.findall('host'):
                        addr_elem = host.find('address')
                        if addr_elem is None: continue
                        ip = addr_elem.get('addr')
                        ports = []
                        for p in host.findall('.//port'):
                            state_elem = p.find('state')
                            if state_elem is not None and state_elem.get('state') == 'open': 
                                ports.append(p.get('portid'))
                        if ports: 
                            clean_lines.append(f"{ip} : {', '.join(ports)}")
                except ET.ParseError as e: 
                    logger.error(f"XML parse error for Nmap {source_file}: {e}")
            elif tool in ['ffuf', 'vhost', 'sni']:
                try:
                    with open(source_file, 'r') as f:
                        data = json.load(f)
                        for res in data.get('results', []): 
                            url = res.get('url') or res.get('host')
                            if url: 
                                clean_lines.append(url)
                except json.JSONDecodeError:
                    pass
            
            if clean_lines:
                with open(clean_file, 'w') as f: 
                    f.write('\n'.join(clean_lines))
                return clean_file
                
        except Exception as e:
            logger.error(f"Failed to generate clean output for {tool}: {e}", exc_info=True)
            
        return None

    def compare_and_notify(self, found_subdomains: List[str]):
        if not found_subdomains: 
            return
        try:
            previous_scan = db.scans.find_one(
                {'targets': self.targets, 'status': 'completed', 'scan_id': {'$ne': self.scan_id}}, 
                sort=[('created_at', -1)]
            )
            
            if not previous_scan:
                send_telegram_alert(f"🆕 **Initial Scan Completed for:** `{self.targets[:50]}`\nFound **{len(found_subdomains)}** subdomains.")
                return

            old_file = Path(f'scans/{previous_scan["scan_id"]}/subfinder.json')
            old_subs = set()
            if old_file.exists():
                old_results = parse_json_lines_helper(old_file)
                old_subs = set(r.get('host') for r in old_results if r.get('host'))
            
            new_subs = set(found_subdomains) - old_subs
            if new_subs:
                count = len(new_subs)
                display_list = list(new_subs)[:15]
                msg = f"🚨 **New Subdomains Found!** 🚨\nTarget: `{self.targets[:30]}...`\nNew: **{count}**\n\n" + "\n".join([f"- `{s}`" for s in display_list])
                if count > 15: 
                    msg += f"\n\n...and {count - 15} more."
                send_telegram_alert(msg)
        except Exception as e: 
            logger.error(f"Failed to compare and notify subdomains: {e}")

    def run(self):
        try:
            db.scans.update_one({'scan_id': self.scan_id}, {'$set': {'status': 'running'}})
        except Exception as e:
            logger.error(f"Failed to set status to running for {self.scan_id}: {e}")
            return

        start_time = datetime.now()
        send_telegram_alert(f"🚀 Scan Started (Resumed: {self.resume_mode})\nTarget: {self.targets[:50]}")
        
        # IMPORTANT: target_list contains ONLY the original user-provided target domains
        # PureDNS bruteforce should ONLY run on these original target domains, NOT on discovered subdomains
        target_list = [t.strip() for t in self.targets.split('\n') if t.strip()]
        
        # current_targets will accumulate all discovered subdomains from subfinder, puredns, etc.
        # This is used for downstream tools like dnsx, httpx, etc.
        current_targets = target_list.copy()
        live_urls = [] 
        nmap_targets = []
        
        def get_args(tool_key: str, default: str = "") -> List[str]:
            return shlex.split(self.tool_args.get(tool_key, default))
        
        proxy_url = self.proxy_config.get('url')
        proxy_tools = self.proxy_config.get('tools', [])
        
        def add_proxy(tool_name: str, cmd_list: List[str]) -> List[str]:
            if proxy_url and tool_name in proxy_tools:
                if tool_name in ['subfinder', 'httpx', 'tlsx', 'katana', 'nuclei']: 
                    cmd_list.extend(['-proxy', proxy_url])
                elif tool_name == 'ffuf': 
                    cmd_list.extend(['-x', proxy_url])
                elif tool_name == 'nmap': 
                    cmd_list.extend(['--proxies', proxy_url])
            return cmd_list

        try:
            # 1. Subfinder - finds known subdomains from passive sources
            if 'subfinder' in self.selected_tools:
                try:
                    if self.resume_mode and self.status.get('stages', {}).get('subfinder', {}).get('status') == 'completed':
                        logger.info("Skipping Subfinder (Completed)")
                        outfile = self.output_dir / 'subfinder.json'
                        if outfile.exists():
                            results = parse_json_lines_helper(outfile)
                            found = [r.get('host') for r in results if r.get('host')]
                            current_targets.extend(found)
                            current_targets = list(set(current_targets))
                            self.update_results('subfinder', len(found))
                    else:
                        if self.stopped: return
                        self.update_stage('subfinder', 'running', 'Finding subdomains...', progress=0)
                        outfile = self.output_dir / 'subfinder.json'
                        base_args = get_args('args_subfinder', '-rl 1 -all')
                        cmd = ['subfinder'] + base_args + ['-silent', '-json', '-o', str(outfile)]
                        cmd = add_proxy('subfinder', cmd)
                        # Subfinder runs on original target domains (target_list)
                        _, err = self.run_command(cmd, input_data='\n'.join(target_list))
                        if not self.stopped:
                            if err and not os.path.exists(outfile): 
                                self.update_stage('subfinder', 'error', _, progress=0)
                            else:
                                results = parse_json_lines_helper(outfile)
                                found = [r.get('host') for r in results if r.get('host')]
                                self.generate_clean_output('subfinder', outfile)
                                self.format_and_send_telegram('subfinder', outfile, caption=f"📄 Subfinder Results for: {self.targets[:30]}")
                                # Add found subdomains to current_targets for downstream tools
                                current_targets.extend(found)
                                current_targets = list(set(current_targets)) 
                                self.update_results('subfinder', len(found))
                                self.update_stage('subfinder', 'completed', f"Found {len(found)} subdomains", progress=100)
                                self.compare_and_notify(found)
                except Exception as e:
                    logger.error(f"Stage 1 Subfinder failed: {e}")
                    self.update_stage('subfinder', 'error', str(e), progress=0)

            # 2. PureDNS - bruteforces subdomains using wordlist
            # IMPORTANT: PureDNS should ONLY run on original target domains (target_list), NOT on discovered subdomains
            # This is because puredns bruteforce tries wordlist entries against the target domain
            # Running it on subdomains would be incorrect behavior
            if 'puredns' in self.selected_tools:
                try:
                    if self.resume_mode and self.status.get('stages', {}).get('puredns', {}).get('status') == 'completed':
                        logger.info("Skipping PureDNS (Completed)")
                        # Only read from puredns_all.txt during resume
                        puredns_all_file = self.output_dir / 'puredns_all.txt'
                        if puredns_all_file.exists():
                            with open(puredns_all_file, 'r') as f:
                                found = [l.strip() for l in f if l.strip()]
                                current_targets.extend(found)
                                current_targets = list(set(current_targets))
                                self.update_results('puredns', len(found))
                    else:
                        if self.stopped: return
                        self.update_stage('puredns', 'running', 'Bruteforcing subdomains...', progress=0)
                        wlist = self.puredns_wordlist_path or 'wordlist.txt'
                        if not os.path.exists(wlist):
                            with open('wordlist.txt', 'w') as f: 
                                f.write("www\nmail\ndev\nadmin\n")
                        
                        resolvers_file = Path('resolvers.txt')
                        if not resolvers_file.exists():
                            resolvers_file = self.output_dir / 'resolvers.txt'
                            with open(resolvers_file, 'w') as f: 
                                f.write("1.1.1.1\n8.8.8.8\n")
                        
                        # Write all results directly to puredns_all.txt
                        puredns_all_file = self.output_dir / 'puredns_all.txt'
                        all_found_subdomains = []
                        
                        # IMPORTANT: Iterate over target_list (original domains), NOT current_targets (which includes discovered subdomains)
                        # PureDNS bruteforce takes a domain and tries wordlist entries as subdomains
                        for domain in target_list:
                            if self.stopped: break
                            # Run puredns bruteforce on the original target domain
                            cmd = ['puredns', 'bruteforce', str(wlist), domain, '-r', str(resolvers_file)]
                            stdout_data, err = self.run_command(cmd)
                            
                            if not err and stdout_data:
                                found_for_domain = [l.strip() for l in stdout_data.split('\n') if l.strip()]
                                all_found_subdomains.extend(found_for_domain)
                        
                        if not self.stopped:
                            # Write all found subdomains to puredns_all.txt
                            if all_found_subdomains:
                                # Remove duplicates and write
                                unique_subdomains = list(set(all_found_subdomains))
                                with open(puredns_all_file, 'w') as f:
                                    f.write('\n'.join(unique_subdomains))
                                total_found = len(unique_subdomains)
                            else:
                                total_found = 0
                            
                            # Add discovered subdomains to current_targets for downstream tools
                            current_targets.extend(all_found_subdomains)
                            current_targets = list(set(current_targets))
                            self.update_results('puredns', total_found)
                            self.update_stage('puredns', 'completed', f"Found {total_found} brute-forced subdomains", progress=100)
                except Exception as e:
                    logger.error(f"Stage 2 PureDNS failed: {e}")
                    self.update_stage('puredns', 'error', str(e), progress=0)

            # --- Merged Results ---
            if ('subfinder' in self.selected_tools or 'puredns' in self.selected_tools) and not self.stopped:
                try:
                    merged_file = self.output_dir / 'merged_subdomains.txt'
                    with open(merged_file, 'w') as f: 
                        f.write('\n'.join(current_targets))
                except Exception as e:
                    logger.error(f"Failed to merge subdomains: {e}")

            # 3. DNSx - resolves all discovered subdomains
            if 'dnsx' in self.selected_tools:
                try:
                    if self.resume_mode and self.status.get('stages', {}).get('dnsx', {}).get('status') == 'completed':
                        logger.info("Skipping DNSx (Completed)")
                        outfile = self.output_dir / 'dnsx.json'
                        if outfile.exists():
                            results = parse_json_lines_helper(outfile)
                            self.update_results('dnsx', len(results))
                            all_ips = set()
                            for res in results:
                                ips = res.get('a', [])
                                if ips: all_ips.update(ips)
                            self.safe_ips = all_ips
                    else:
                        if self.stopped: return
                        self.update_stage('dnsx', 'running', 'Resolving DNS records...', progress=0)
                        outfile = self.output_dir / 'dnsx.json'
                        # DNSx resolves all discovered subdomains (current_targets)
                        _, err = self.run_command(['dnsx', '-silent', '-json', '-a', '-o', str(outfile)], input_data='\n'.join(current_targets))
                        if not err and not self.stopped:
                            self.generate_clean_output('dnsx', outfile)
                            self.format_and_send_telegram('dnsx', outfile, caption=f"📄 DNSx Results")
                            results = parse_json_lines_helper(outfile)
                            all_ips = set()
                            for res in results:
                                ips = res.get('a', [])
                                if ips: all_ips.update(ips)
                            self.safe_ips = all_ips
                            self.update_results('dnsx', len(results))
                            self.update_stage('dnsx', 'completed', f"Resolved {len(results)} records", progress=100)
                        elif err:
                            self.update_stage('dnsx', 'error', "DNSx failed to run", progress=0)
                except Exception as e:
                    logger.error(f"Stage 3 DNSx failed: {e}")
                    self.update_stage('dnsx', 'error', str(e), progress=0)

            # 4. Cut-CDN
            if 'cut-cdn' in self.selected_tools:
                try:
                    if self.resume_mode and self.status.get('stages', {}).get('cut-cdn', {}).get('status') == 'completed':
                        logger.info("Skipping Cut-CDN (Completed)")
                        active_ips_file = self.output_dir / 'active_ips.txt'
                        if active_ips_file.exists():
                            self.safe_ips = set(active_ips_file.read_text().splitlines())
                            removed_count = self.status.get('results', {}).get('cut_cdn', 0)
                            self.update_results('cut_cdn', removed_count)
                    else:
                        if self.safe_ips:
                            if self.stopped: return
                            self.update_stage('cut-cdn', 'running', 'Filtering CDN IPs...', progress=0)
                            initial_count = len(self.safe_ips)
                            out, err = self.run_command(['cut-cdn'], input_data='\n'.join(self.safe_ips))
                            if not err and out and not self.stopped:
                                self.safe_ips = set(l.strip() for l in out.split('\n') if l.strip())
                                active_ips_file = self.output_dir / 'active_ips.txt'
                                with open(active_ips_file, 'w') as f: 
                                    f.write('\n'.join(self.safe_ips))
                                removed_count = initial_count - len(self.safe_ips)
                                self.update_results('cut_cdn', removed_count) 
                                self.format_and_send_telegram('cut-cdn', active_ips_file, caption=f"📄 Cut-CDN Results (Active IPs)")
                                self.update_stage('cut-cdn', 'completed', f"Filtered {removed_count} CDN IPs", progress=100)
                            elif err:
                                logger.error(f"Cut-CDN failed: {out}")
                                self.update_stage('cut-cdn', 'error', f"Error executing tool", progress=0)
                            else:
                                removed_count = initial_count
                                self.safe_ips = set()
                                self.update_results('cut_cdn', removed_count)
                                self.update_stage('cut-cdn', 'completed', f"Filtered all {removed_count} IPs", progress=100)
                        else:
                            self.update_stage('cut-cdn', 'skipped', "No IPs to filter", progress=100)
                except Exception as e:
                    logger.error(f"Stage 4 Cut-CDN failed: {e}")
                    self.update_stage('cut-cdn', 'error', str(e), progress=0)
            
            # 5. Nmap (Moved Up)
            if 'nmap' in self.selected_tools:
                try:
                    if self.resume_mode and self.status.get('stages', {}).get('nmap', {}).get('status') == 'completed':
                        logger.info("Skipping Nmap (Completed)")
                    else:
                        targets_scan = list(self.safe_ips) if 'cut-cdn' in self.selected_tools and self.safe_ips else []
                        if targets_scan and not self.stopped:
                            self.update_stage('nmap', 'running', 'Scanning open ports...', progress=0)
                            tfile = self.output_dir / 'nmap_targets.txt'
                            with open(tfile, 'w') as f: 
                                f.write('\n'.join(list(targets_scan)))
                            outfile = self.output_dir / 'nmap.xml'
                            base_args = get_args('args_nmap', '-sV -T4 -Pn --open')
                            cmd = ['nmap', '-iL', str(tfile)] + base_args + ['-oX', str(outfile)]
                            cmd = add_proxy('nmap', cmd)
                            _, err = self.run_command(cmd)
                            if not err and not self.stopped:
                                self.generate_clean_output('nmap', outfile)
                                self.format_and_send_telegram('nmap', outfile, caption=f"📄 Nmap Results")
                                self.update_stage('nmap', 'completed', "Finished port scan", progress=100)
                            elif err:
                                self.update_stage('nmap', 'error', "Nmap failed", progress=0)
                        else: 
                            self.update_stage('nmap', 'skipped', "No non-CDN IPs to scan", progress=100)
                except Exception as e:
                    logger.error(f"Stage 5 Nmap failed: {e}")
                    self.update_stage('nmap', 'error', str(e), progress=0)
            
            # Extract IP:Port from Nmap for other tools safely
            try:
                nmap_outfile = self.output_dir / 'nmap.xml'
                if nmap_outfile.exists() and not self.stopped:
                    tree = ET.parse(nmap_outfile)
                    root = tree.getroot()
                    for host in root.findall('host'):
                        addr_elem = host.find('address')
                        if addr_elem is None: continue
                        ip_addr = addr_elem.get('addr')
                        for port in host.findall('.//port'):
                            state_elem = port.find('state')
                            if state_elem is not None and state_elem.get('state') == 'open':
                                nmap_targets.append(f"{ip_addr}:{port.get('portid')}")
            except ET.ParseError as e:
                logger.error(f"Failed to parse nmap.xml for httpx: {e}")
            except Exception as e:
                logger.error(f"Unexpected error extracting Nmap targets: {e}")

            # 6. TLSx
            if 'tlsx' in self.selected_tools:
                try:
                    if self.resume_mode and self.status.get('stages', {}).get('tlsx', {}).get('status') == 'completed':
                        logger.info("Skipping TLSx (Completed)")
                        outfile = self.output_dir / 'tlsx.json'
                        if outfile.exists(): 
                            self.update_results('tlsx', count_file_lines(outfile))
                    else:
                        if self.stopped: return
                        self.update_stage('tlsx', 'running', 'Scanning TLS certificates...', progress=0)
                        outfile = self.output_dir / 'tlsx.json'
                        cmd = ['tlsx', '-silent', '-json', '-o', str(outfile)]
                        cmd = add_proxy('tlsx', cmd)
                        _, err = self.run_command(cmd, input_data='\n'.join(current_targets))
                        if not err and not self.stopped:
                            self.generate_clean_output('tlsx', outfile)
                            self.format_and_send_telegram('tlsx', outfile, caption=f"📄 TLSx Results")
                            self.update_results('tlsx', count_file_lines(outfile))
                            self.update_stage('tlsx', 'completed', "Finished TLS scan", progress=100)
                        elif err:
                            self.update_stage('tlsx', 'error', "TLSx failed", progress=0)
                except Exception as e:
                    logger.error(f"Stage 6 TLSx failed: {e}")
                    self.update_stage('tlsx', 'error', str(e), progress=0)

            # 7. HTTPx
            if 'httpx' in self.selected_tools:
                try:
                    if self.resume_mode and self.status.get('stages', {}).get('httpx', {}).get('status') == 'completed':
                        logger.info("Skipping HTTPx (Completed)")
                        outfile = self.output_dir / 'httpx.json'
                        if outfile.exists():
                            results = parse_json_lines_helper(outfile)
                            live_urls = [r.get('url') for r in results if r.get('url')]
                            self.update_results('httpx', count_file_lines(outfile))
                    else:
                        httpx_input_targets = list(set(current_targets + nmap_targets))
                        if httpx_input_targets and not self.stopped:
                            self.update_stage('httpx', 'running', 'Probing for web servers...', progress=0)
                            outfile = self.output_dir / 'httpx.json'
                            base_args = get_args('args_httpx', '-probe -tech-detect')
                            cmd = ['httpx'] + base_args + ['-silent', '-json', '-o', str(outfile)]
                            cmd = add_proxy('httpx', cmd)
                            _, err = self.run_command(cmd, input_data='\n'.join(httpx_input_targets))
                            
                            if not err and not self.stopped:
                                self.generate_clean_output('httpx', outfile)
                                self.format_and_send_telegram('httpx', outfile, caption=f"📄 HTTPx Results")
                                self.update_results('httpx', count_file_lines(outfile))
                                results = parse_json_lines_helper(outfile)
                                live_urls = [r.get('url') for r in results if r.get('url')]
                                self.update_stage('httpx', 'completed', f"Found {len(live_urls)} web servers", progress=100)
                            elif err:
                                self.update_stage('httpx', 'error', "HTTPx failed", progress=0)
                        else:
                            self.update_stage('httpx', 'skipped', "No targets for httpx", progress=100)
                except Exception as e:
                    logger.error(f"Stage 7 HTTPx failed: {e}")
                    self.update_stage('httpx', 'error', str(e), progress=0)

            # 8. Katana
            if 'katana' in self.selected_tools:
                try:
                    if self.resume_mode and self.status.get('stages', {}).get('katana', {}).get('status') == 'completed':
                        logger.info("Skipping Katana (Completed)")
                        outfile = self.output_dir / 'katana.jsonl'
                        if outfile.exists(): 
                            self.update_results('katana', count_file_lines(outfile))
                    else:
                        targets_kat = live_urls if live_urls else current_targets
                        if targets_kat and not self.stopped:
                            self.update_stage('katana', 'running', 'Crawling web endpoints...', progress=0)
                            list_file = self.output_dir / 'katana_targets.txt'
                            list_file.write_text('\n'.join(targets_kat))
                            outfile = self.output_dir / 'katana.jsonl'
                            base_args = get_args('args_katana', '-d 3 -timeout 30')
                            cmd = ['katana', '-list', str(list_file)] + base_args + ['-silent', '-jsonl', '-o', str(outfile)]
                            cmd = add_proxy('katana', cmd)
                            _, err = self.run_command(cmd)
                            
                            if not err and not self.stopped:
                                count = count_file_lines(outfile)
                                self.update_results('katana', count) 
                                self.generate_clean_output('katana', outfile)
                                self.update_stage('katana', 'completed', f"Crawled {count} endpoints", progress=100)
                            elif err:
                                self.update_stage('katana', 'error', "Katana failed", progress=0)
                        else: 
                            self.update_stage('katana', 'skipped', "No targets to crawl", progress=100)
                except Exception as e:
                    logger.error(f"Stage 8 Katana failed: {e}")
                    self.update_stage('katana', 'error', str(e), progress=0)

            # 9. VHost
            if 'vhost' in self.selected_tools:
                try:
                    if self.resume_mode and self.status.get('stages', {}).get('vhost', {}).get('status') == 'completed':
                        logger.info("Skipping VHost (Completed)")
                    else:
                        if self.stopped: return
                        self.update_stage('vhost', 'running', 'Phase 1: Bruteforce...', progress=0)
                        wlist = self.ffuf_wordlist_path or 'wordlist.txt'
                        if not os.path.exists(wlist):
                            with open('wordlist.txt', 'w') as f: 
                                f.write("dev\nadmin\n")
                        
                        found = 0
                        ips_to_scan = list(self.safe_ips) if self.safe_ips else []
                        
                        if ips_to_scan:
                            base_args = get_args('args_vhost', '-ac -t 10 -rate 5')
                            # Phase 1: Bruteforce with provided wordlist on original target domains
                            for domain in target_list:
                                if self.stopped: break
                                for ip in ips_to_scan:
                                    if self.stopped: break
                                    outfile = self.output_dir / f'vhost_brute_{domain}_{ip.replace(".", "_")}.json'
                                    cmd = ['ffuf', '-u', f"http://{ip}", '-H', f'Host: FUZZ.{domain}', '-w', str(wlist)] + base_args + ['-o', str(outfile), '-of', 'json', '-s']
                                    cmd = add_proxy('ffuf', cmd)
                                    self.run_command(cmd)
                                    if os.path.exists(outfile):
                                        try: 
                                            with open(outfile) as jf:
                                                found += len(json.load(jf).get('results', []))
                                        except json.JSONDecodeError: pass
                            
                            if not self.stopped:
                                # Phase 2: Discover with found subdomains
                                self.update_stage('vhost', 'running', 'Phase 2: Discovering...', progress=50)
                                subdomain_wordlist = self.output_dir / 'merged_subdomains.txt'
                                if subdomain_wordlist.exists() and subdomain_wordlist.stat().st_size > 0:
                                    for ip in ips_to_scan:
                                        if self.stopped: break
                                        outfile = self.output_dir / f'vhost_discover_{ip.replace(".", "_")}.json'
                                        cmd = ['ffuf', '-u', f"http://{ip}", '-H', 'Host: FUZZ', '-w', str(subdomain_wordlist)] + base_args + ['-o', str(outfile), '-of', 'json', '-s']
                                        cmd = add_proxy('ffuf', cmd)
                                        self.run_command(cmd)
                                        if outfile.exists():
                                            try: 
                                                with open(outfile) as jf:
                                                    found += len(json.load(jf).get('results', []))
                                            except json.JSONDecodeError: pass
                            
                            if not self.stopped:
                                self.update_results('vhost', found)
                                vhost_all = set()
                                for vf in self.output_dir.glob('vhost_*.json'):
                                    try:
                                        with open(vf) as jf:
                                            d = json.load(jf)
                                            for r in d.get('results', []):
                                                val = r.get('host') or r.get('url')
                                                if val: vhost_all.add(val)
                                    except Exception: pass
                                if vhost_all:
                                    with open(self.output_dir / 'vhost_all.txt', 'w') as f:
                                        f.write('\n'.join(sorted(list(vhost_all))))
                                
                                self.update_stage('vhost', 'completed', f"Found {found} vhosts", progress=100)
                        else: 
                            self.update_stage('vhost', 'skipped', "No non-CDN IPs to scan", progress=100)
                except Exception as e:
                    logger.error(f"Stage 9 VHost failed: {e}")
                    self.update_stage('vhost', 'error', str(e), progress=0)

            # 10. SNI Check using FFUF
            if 'sni' in self.selected_tools:
                try:
                    if self.resume_mode and self.status.get('stages', {}).get('sni', {}).get('status') == 'completed':
                        logger.info("Skipping SNI Check (Completed)")
                        outfile = self.output_dir / 'sni.json'
                        if outfile.exists():
                            try:
                                with open(outfile, 'r') as f: 
                                    data = json.load(f)
                                    self.update_results('sni', len(data.get('results', [])))
                            except json.JSONDecodeError: pass
                    else:
                        if self.stopped: return
                        self.update_stage('sni', 'running', 'Checking SNI with FFUF...', progress=0)
                        
                        subdomain_wordlist = self.output_dir / 'merged_subdomains.txt'
                        ips_to_scan = list(self.safe_ips) if self.safe_ips else []
                        
                        if ips_to_scan and subdomain_wordlist.exists() and subdomain_wordlist.stat().st_size > 0:
                            base_args = get_args('args_vhost', '-ac -t 10 -rate 5')
                            all_results = []
                            
                            for ip in ips_to_scan:
                                if self.stopped: break
                                outfile = self.output_dir / f'sni_{ip.replace(".", "_")}.json'
                                cmd = ['ffuf', '-u', f"https://{ip}", '-w', str(subdomain_wordlist), '-sni', 'FUZZ'] + base_args + ['-o', str(outfile), '-of', 'json', '-s']
                                cmd = add_proxy('ffuf', cmd)
                                self.run_command(cmd)
                                
                                if outfile.exists():
                                    try:
                                        with open(outfile, 'r') as f:
                                            data = json.load(f)
                                            results = data.get('results', [])
                                            all_results.extend(results)
                                    except json.JSONDecodeError: pass
                            
                            if not self.stopped:
                                final_outfile = self.output_dir / 'sni.json'
                                with open(final_outfile, 'w') as f: 
                                    json.dump({'results': all_results}, f)
                                
                                self.generate_clean_output('sni', final_outfile)
                                self.format_and_send_telegram('sni', final_outfile, caption=f"📄 SNI Check Results")
                                self.update_results('sni', len(all_results))
                                self.update_stage('sni', 'completed', f"Found {len(all_results)} valid SNIs", progress=100)
                        else:
                            self.update_stage('sni', 'skipped', "No IPs or subdomains for SNI check", progress=100)
                except Exception as e:
                    logger.error(f"Stage 10 SNI failed: {e}")
                    self.update_stage('sni', 'error', str(e), progress=0)

            # 11. Nuclei
            if 'nuclei' in self.selected_tools:
                try:
                    if self.resume_mode and self.status.get('stages', {}).get('nuclei', {}).get('status') == 'completed':
                        logger.info("Skipping Nuclei (Completed)")
                        outfile = self.output_dir / 'nuclei.jsonl'
                        if outfile.exists():
                            self.update_results('nuclei', count_file_lines(outfile))
                    else:
                        if self.stopped: return
                        t_nuc = list(set(live_urls + nmap_targets)) if live_urls or nmap_targets else current_targets
                        if t_nuc:
                            self.update_stage('nuclei', 'running', 'Scanning for vulnerabilities...', progress=0)
                            tfile = self.output_dir / 'nuclei_targets.txt'
                            with open(tfile, 'w') as f: 
                                f.write('\n'.join(t_nuc))
                            outfile = self.output_dir / 'nuclei.jsonl'
                            base_args = get_args('args_nuclei', '-rl 150 -c 25')
                            cmd = ['nuclei', '-l', str(tfile)] + base_args + ['-silent', '-jsonl', '-o', str(outfile)]
                            cmd = add_proxy('nuclei', cmd)
                            if self.nuclei_categories: 
                                cmd.extend(['-t', ','.join(self.nuclei_categories)])
                            if self.nuclei_severities: 
                                cmd.extend(['-s', ','.join(self.nuclei_severities)])
                            _, err = self.run_command(cmd)

                            if not self.stopped:
                                self.generate_clean_output('nuclei', outfile)
                                self.format_and_send_telegram('nuclei', outfile, caption=f"📄 Nuclei Results (Severities: {','.join(self.nuclei_severities) or 'ALL'})")
                                count = count_file_lines(outfile)
                                self.update_results('nuclei', count)
                                self.update_stage('nuclei', 'completed', f"Found {count} issues", progress=100)
                        else:
                            self.update_stage('nuclei', 'skipped', "No targets to scan", progress=100)
                except Exception as e:
                    logger.error(f"Stage 11 Nuclei failed: {e}")
                    self.update_stage('nuclei', 'error', str(e), progress=0)

            # 12. FFUF
            if 'ffuf' in self.selected_tools:
                try:
                    if self.resume_mode and self.status.get('stages', {}).get('ffuf', {}).get('status') == 'completed':
                        logger.info("Skipping FFUF (Completed)")
                        outfile = self.output_dir / 'ffuf_dir.json'
                        if outfile.exists():
                            try:
                                with open(outfile, 'r') as f: 
                                    data = json.load(f)
                                    self.update_results('ffuf', len(data.get('results', [])))
                            except json.JSONDecodeError: pass
                    else:
                        t_ffuf = live_urls if live_urls else []
                        if t_ffuf and not self.stopped:
                            self.update_stage('ffuf', 'running', 'Fuzzing directories...', progress=0)
                            wlist = self.ffuf_wordlist_path or 'wordlist.txt'
                            if not os.path.exists(wlist):
                                with open('wordlist.txt', 'w') as f: 
                                    f.write("admin\n")
                            outfile = self.output_dir / 'ffuf_dir.json'
                            base_args = get_args('args_ffuf', '-ac')
                            all_results = []
                            
                            for url in t_ffuf:
                                if self.stopped: break
                                target = f"{url}/FUZZ"
                                temp_outfile = self.output_dir / f'ffuf_temp_{hash(url)}.json'
                                cmd = ['ffuf', '-u', target, '-w', str(wlist)] + base_args + ['-o', str(temp_outfile), '-of', 'json', '-s']
                                cmd = add_proxy('ffuf', cmd)
                                self.run_command(cmd)
                                if temp_outfile.exists():
                                    try:
                                        with open(temp_outfile, 'r') as f:
                                            data = json.load(f)
                                            all_results.extend(data.get('results', []))
                                        temp_outfile.unlink() # Clean up
                                    except Exception as e:
                                        logger.error(f"Failed parsing FFUF output for {url}: {e}")
                            
                            if not self.stopped:
                                with open(outfile, 'w') as f: 
                                    json.dump({'results': all_results}, f)
                                
                                self.generate_clean_output('ffuf', outfile)
                                self.format_and_send_telegram('ffuf', outfile, caption=f"📄 FFUF Results")
                                self.update_results('ffuf', len(all_results))
                                self.update_stage('ffuf', 'completed', "Finished directory fuzzing", progress=100)
                        else:
                            self.update_stage('ffuf', 'skipped', "No web servers to fuzz", progress=100)
                except Exception as e:
                    logger.error(f"Stage 12 FFUF failed: {e}")
                    self.update_stage('ffuf', 'error', str(e), progress=0)

            # 13. Gowitness
            if 'gowitness' in self.selected_tools:
                try:
                    if self.resume_mode and self.status.get('stages', {}).get('gowitness', {}).get('status') == 'completed':
                        logger.info("Skipping Gowitness (Completed)")
                        screenshot_dir = self.output_dir / 'screenshots'
                        if screenshot_dir.exists():
                            count = len(list(screenshot_dir.glob('*.png')))
                            self.update_results('gowitness', count)
                    else:
                        if self.stopped: return
                        t_gw = live_urls if live_urls else []
                        if t_gw:
                            self.update_stage('gowitness', 'running', 'Taking screenshots...', progress=0)
                            gw_targets_file = self.output_dir / 'gowitness_targets.txt'
                            with open(gw_targets_file, 'w') as f: 
                                f.write('\n'.join(t_gw))
                            screenshot_dir = self.output_dir / 'screenshots'
                            screenshot_dir.mkdir(exist_ok=True)
                            db_path = self.output_dir / 'gowitness.sqlite3'
                            base_args = get_args('args_gowitness', '--disable-logging')
                            cmd = ['gowitness', 'file', '-f', str(gw_targets_file), '--screenshot-path', str(screenshot_dir), '--db-path', str(db_path)] + base_args
                            if proxy_url and 'gowitness' in proxy_tools:
                                 cmd.extend(['--proxy', proxy_url])
                            self.run_command(cmd)
                            
                            if not self.stopped:
                                count = len(list(screenshot_dir.glob('*.png')))
                                self.update_results('gowitness', count)
                                self.update_stage('gowitness', 'completed', f"Captured {count} screenshots", progress=100)
                        else:
                            self.update_stage('gowitness', 'skipped', "No web servers to screenshot", progress=100)
                except Exception as e:
                    logger.error(f"Stage 13 Gowitness failed: {e}")
                    self.update_stage('gowitness', 'error', str(e), progress=0)

            if not self.stopped:
                self.status['status'] = 'completed'
                try:
                    db.scans.update_one({'scan_id': self.scan_id}, {'$set': {'status': 'completed', 'results': self.status['results']}})
                except Exception as e:
                    logger.error(f"Failed saving final state for {self.scan_id}: {e}")
                    
                end_time = datetime.now()
                duration = end_time - start_time
                send_telegram_alert(f"✅ Scan Finished\nTarget: {self.targets[:50]}\nDuration: {str(duration).split('.')[0]}")
            
        except Exception as e:
            logger.critical(f"Scan Pipeline failed entirely: {e}", exc_info=True)
            if not self.stopped:
                self.status['status'] = 'error'
                try:
                    db.scans.update_one({'scan_id': self.scan_id}, {'$set': {'status': 'error', 'error': str(e)}})
                except Exception as db_err:
                    logger.error(f"Failed to save error state to DB: {db_err}")
        finally:
            if self.scan_id in scan_queue and self.status['status'] in ['completed', 'error', 'stopped']:
                # Clean up memory reference when completely done.
                pass 

# --- Scheduler Logic ---
def scheduler_loop():
    """Background thread to dispatch scheduled and recurring scans."""
    logger.info("⏰ Scheduler thread started successfully.")
    while True:
        try:
            now_str = datetime.now().isoformat()
            # Fetch due scans
            due_scans = db.scans.find({'status': 'scheduled', 'scheduled_time': {'$lte': now_str}})
            
            for doc in due_scans:
                scan_id = doc['scan_id']
                if scan_id in scan_queue: 
                    continue 
                    
                logger.info(f"🚀 Starting scheduled scan: {scan_id}")

                freq = doc.get('frequency', 'once')
                if freq != 'once':
                    try:
                        curr_time = datetime.fromisoformat(doc['scheduled_time'])
                        next_time = None
                        if freq == 'daily': next_time = curr_time + timedelta(days=1)
                        elif freq == 'weekly': next_time = curr_time + timedelta(weeks=1)
                        elif freq == 'monthly': next_time = curr_time + timedelta(days=30)
                        
                        if next_time:
                            new_scan_id = generate_unique_scan_id()
                            new_doc = doc.copy()
                            new_doc.update({
                                'scan_id': new_scan_id,
                                'scheduled_time': next_time.isoformat(),
                                'created_at': datetime.now().isoformat(),
                                'status': 'scheduled', 'stages': {}, 'results': {}
                            })
                            if '_id' in new_doc: del new_doc['_id']
                            db.scans.insert_one(new_doc)
                            logger.info(f"🔄 Scheduled next {freq} scan: {new_scan_id} at {next_time}")
                    except Exception as e:
                        logger.error(f"Error rescheduling recurring scan {scan_id}: {e}")

                config = doc.get('config', {})
                runner = ScanRunner(
                    scan_id=scan_id,
                    targets=doc.get('targets', ''),
                    selected_tools=config.get('tools', REQUIRED_TOOLS),
                    nuclei_categories=config.get('nuclei_categories', []),
                    nuclei_severities=config.get('nuclei_severities', []),
                    puredns_wordlist_path=config.get('puredns_wordlist_path'),
                    ffuf_wordlist_path=config.get('ffuf_wordlist_path'),
                    tool_args=config.get('tool_args', {}),
                    proxy_config=config.get('proxy_config', {})
                )
                scan_queue[scan_id] = runner
                threading.Thread(target=runner.run, daemon=True).start()
                
        except (ConnectionFailure, ServerSelectionTimeoutError):
            logger.error("Scheduler: Lost connection to MongoDB. Retrying...")
        except Exception as e:
            logger.error(f"Scheduler loop error: {e}", exc_info=True)
            
        time.sleep(10)

def continuous_subfinder_monitor():
    """Background thread that runs subfinder every 4 hours on saved targets to find and alert on new subdomains."""
    logger.info("⏰ Continuous Subfinder monitor started (wakes every 4 hours).")
    while True:
        try:
            # 1. Fetch saved target domains
            targets_cursor = db.saved_targets.find({}, {'value': 1})
            targets = [t['value'].strip() for t in targets_cursor if t.get('value')]
            
            # Filter out IPs and CIDR notations to just test top level targets/domains
            domains = [t for t in targets if not any(c in t for c in ['/', ':']) and not t.replace('.','').isnumeric()]
            
            if domains:
                logger.info(f"🔍 Running periodic Subfinder against {len(domains)} saved domain targets...")
                
                # Create a temporary input file
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tf:
                    tf.write('\n'.join(domains))
                    targets_file = tf.name
                
                out_file = targets_file + "_out.json"
                subfinder_path = get_tool_path('subfinder')
                cmd = [subfinder_path, '-dL', targets_file, '-json', '-o', out_file, '-silent', '-all']
                
                # Execute Subfinder
                try:
                    subprocess.run(cmd, capture_output=True, text=True, timeout=7200) # 2 hours max
                except subprocess.TimeoutExpired:
                    logger.error("Periodic Subfinder timed out.")
                except Exception as e:
                    logger.error(f"Periodic Subfinder execution failed: {e}")
                
                # Process Results securely into memory
                if os.path.exists(out_file):
                    found_subs = set()
                    with open(out_file, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            if not line.strip(): continue
                            try:
                                data = json.loads(line)
                                sub = data.get('host')
                                if sub: 
                                    found_subs.add(sub)
                            except json.JSONDecodeError: 
                                pass

                    if found_subs:
                        # Find which of these are genuinely new by querying the DB
                        existing_cursor = db.known_subdomains.find({'subdomain': {'$in': list(found_subs)}})
                        existing_subs = set(doc['subdomain'] for doc in existing_cursor)
                        
                        new_subs_set = found_subs - existing_subs
                        new_subdomains = list(new_subs_set)
                        
                        # If there are new subdomains, insert them and alert
                        if new_subdomains:
                            # Chunk inserts for safety
                            docs_to_insert = [{'subdomain': s, 'discovered_at': datetime.now().isoformat()} for s in new_subdomains]
                            chunk_size = 10000
                            for i in range(0, len(docs_to_insert), chunk_size):
                                db.known_subdomains.insert_many(docs_to_insert[i:i+chunk_size], ordered=False)
                                
                            count = len(new_subdomains)
                            logger.info(f"✅ Periodic monitor found {count} new subdomains.")
                            msg = f"🔍 **Periodic Subfinder Monitor**\nFound **{count}** new subdomains for saved targets!\n\n"
                            
                            display_list = new_subdomains[:100]
                            msg += "\n".join([f"- `{s}`" for s in display_list])
                            if count > 100:
                                msg += f"\n\n...and {count - 100} more."
                                
                            send_telegram_alert(msg)
                        else:
                            logger.info("ℹ️ Periodic monitor finished. No new subdomains found.")
                    
                    # Cleanup output file
                    os.remove(out_file)
                
                # Cleanup targets file
                if os.path.exists(targets_file):
                    os.remove(targets_file)
                    
        except Exception as e:
            logger.error(f"Error in continuous subfinder monitor: {e}", exc_info=True)
        
        # Sleep for exactly 4 hours (14400 seconds) before running again
        time.sleep(14400)


# --- Routes ---

@socketio.on('join')
def on_join(scan_id):
    join_room(scan_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            error = "Invalid Credentials. Please try again."
    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template_string(HTML_TEMPLATE)

# --- API Routes ---

@app.route('/api/targets', methods=['GET'])
@login_required
def get_targets():
    try:
        targets = list(db.saved_targets.find({}, {'_id': 0, 'value': 1}).sort('value', 1))
        return jsonify([t['value'] for t in targets])
    except Exception as e:
        logger.error(f"Failed fetching targets: {e}")
        return jsonify({'error': 'Failed to fetch targets'}), 500

@app.route('/api/targets', methods=['POST'])
@login_required
def add_target():
    data = request.json
    if not data or 'target' not in data:
        return jsonify({'error': 'Invalid request format'}), 400
        
    target = str(data.get('target', '')).strip()
    if not target or len(target) > 255: 
        return jsonify({'error': 'Invalid or empty target'}), 400
        
    try:
        db.saved_targets.insert_one({'value': target, 'created_at': datetime.now()})
        return jsonify({'success': True})
    except Exception as e: 
        return jsonify({'error': 'Target already exists or database error'}), 400

@app.route('/api/local_wordlists', methods=['GET'])
@login_required
def list_local_wordlists():
    try:
        files = [f for f in os.listdir('.') if os.path.isfile(f) and f.endswith('.txt')]
        return jsonify(files)
    except Exception as e: 
        logger.error(f"Failed listing wordlists: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/start_scan', methods=['POST'])
@login_required
def start_scan():
    targets = request.form.get('targets')
    if not targets or not targets.strip(): 
        return jsonify({'error': 'Targets cannot be empty'}), 400
    
    # Use unique scan ID with UUID suffix to avoid collisions
    scan_id = generate_unique_scan_id()
    
    puredns_path = request.form.get('wordlist_puredns_select')
    ffuf_path = request.form.get('wordlist_ffuf_select')

    tools = request.form.getlist('tools') or REQUIRED_TOOLS
    nuclei_categories = request.form.getlist('nuclei_category')
    nuclei_severities = request.form.getlist('nuclei_severity')
    
    tool_args = {f'args_{k}': str(request.form.get(f'args_{k}', '')) for k in ['subfinder', 'httpx', 'katana', 'nmap', 'vhost', 'ffuf', 'nuclei', 'gowitness']}
    proxy_config = {'url': str(request.form.get('proxy_url', '')).strip(), 'tools': request.form.getlist('proxy_tools')}

    config = {
        'tools': tools,
        'nuclei_categories': nuclei_categories,
        'nuclei_severities': nuclei_severities,
        'puredns_wordlist_path': puredns_path,
        'ffuf_wordlist_path': ffuf_path,
        'tool_args': tool_args,
        'proxy_config': proxy_config
    }
    
    scan_doc = {
        'scan_id': scan_id, 'targets': targets, 'config': config, 
        'frequency': request.form.get('frequency', 'once'),
        'stages': {}, 'results': {}, 'created_at': datetime.now().isoformat()
    }

    scheduled_time = request.form.get('scheduled_time')
    try:
        if scheduled_time:
            scan_doc['status'] = 'scheduled'
            scan_doc['scheduled_time'] = scheduled_time
            db.scans.insert_one(scan_doc)
            return jsonify({'scan_id': scan_id, 'status': 'scheduled'})
        else:
            scan_doc['status'] = 'running'
            db.scans.insert_one(scan_doc)
            runner = ScanRunner(
                scan_id=scan_id, 
                targets=targets, 
                selected_tools=tools,
                nuclei_categories=nuclei_categories,
                nuclei_severities=nuclei_severities,
                puredns_wordlist_path=puredns_path,
                ffuf_wordlist_path=ffuf_path,
                tool_args=tool_args,
                proxy_config=proxy_config
            )
            scan_queue[scan_id] = runner
            threading.Thread(target=runner.run, daemon=True).start()
            return jsonify({'scan_id': scan_id, 'status': 'running'})
    except DuplicateKeyError as e:
        logger.error(f"Duplicate scan_id {scan_id}: {e}")
        return jsonify({'error': 'Scan ID collision, please try again'}), 500
    except Exception as e:
        logger.error(f"Failed to start scan: {e}", exc_info=True)
        return jsonify({'error': 'Database error while starting scan'}), 500

@app.route('/api/stop_scan/<scan_id>', methods=['POST'])
@login_required
def stop_scan_route(scan_id):
    try:
        if scan_id in scan_queue:
            scan_queue[scan_id].stop()
            return jsonify({'success': True, 'message': 'Scan stopping...'})
        db.scans.update_one({'scan_id': scan_id}, {'$set': {'status': 'stopped'}})
        return jsonify({'success': True, 'message': 'Marked as stopped'})
    except Exception as e:
        logger.error(f"Error stopping scan {scan_id}: {e}")
        return jsonify({'error': 'Failed to stop scan'}), 500

@app.route('/api/resume_scan/<scan_id>', methods=['POST'])
@login_required
def resume_scan_route(scan_id):
    try:
        doc = db.scans.find_one({'scan_id': scan_id})
        if not doc: 
            return jsonify({'error': 'Scan not found'}), 404
        if doc.get('status') == 'running' and scan_id in scan_queue:
            return jsonify({'error': 'Scan is already running'}), 400

        config = doc.get('config', {})
        runner = ScanRunner(
            scan_id=scan_id, 
            targets=doc.get('targets', ''),
            selected_tools=config.get('tools', REQUIRED_TOOLS),
            nuclei_categories=config.get('nuclei_categories', []),
            nuclei_severities=config.get('nuclei_severities', []),
            puredns_wordlist_path=config.get('puredns_wordlist_path'),
            ffuf_wordlist_path=config.get('ffuf_wordlist_path'),
            tool_args=config.get('tool_args', {}),
            proxy_config=config.get('proxy_config', {}),
            resume_mode=True
        )
        scan_queue[scan_id] = runner
        threading.Thread(target=runner.run, daemon=True).start()
        return jsonify({'success': True, 'status': 'running'})
    except Exception as e:
        logger.error(f"Error resuming scan {scan_id}: {e}")
        return jsonify({'error': 'Failed to resume scan'}), 500

@app.route('/scan_status/<scan_id>')
@login_required
def scan_status(scan_id):
    try:
        if scan_id in scan_queue: 
            return jsonify(scan_queue[scan_id].status)
        doc = db.scans.find_one({'scan_id': scan_id}, {'_id': 0})
        return jsonify(doc) if doc else (jsonify({'error': 'Not found'}), 404)
    except Exception as e:
        logger.error(f"Error fetching status for {scan_id}: {e}")
        return jsonify({'error': 'Database error'}), 500

@app.route('/download/<scan_id>')
@login_required
def download_results(scan_id):
    # Validation against path traversal
    safe_scan_id = secure_filename(scan_id)
    scan_dir = Path(f'scans/{safe_scan_id}')
    
    if not scan_dir.exists(): 
        return jsonify({'error': 'Files not found'}), 404
        
    try:
        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            for f in scan_dir.rglob('*'): 
                zf.write(f, f.relative_to(scan_dir))
        memory_file.seek(0)
        return send_file(memory_file, as_attachment=True, download_name=f'scan_{safe_scan_id}.zip', mimetype='application/zip')
    except Exception as e:
        logger.error(f"Error zipping scan files for {safe_scan_id}: {e}")
        return jsonify({'error': 'Failed to create zip archive'}), 500

@app.route('/api/history', methods=['GET'])
@login_required
def api_history():
    query = {}
    if request.args.get('status'): 
        query['status'] = request.args.get('status')
    if request.args.get('target'): 
        # Escape user input for regex to avoid ReDoS
        escaped_target = request.args.get('target', '').replace('.', '\\.').replace('*', '.*')
        query['targets'] = {'$regex': escaped_target, '$options': 'i'}
    
    date_filter = {}
    if request.args.get('start_date'): 
        date_filter['$gte'] = request.args.get('start_date')
    if request.args.get('end_date'): 
        date_filter['$lte'] = request.args.get('end_date')
    if date_filter: 
        query['created_at'] = date_filter
        
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
    except ValueError: 
        page = 1
        per_page = 10
    
    try:
        total = db.scans.count_documents(query)
        scans = list(db.scans.find(query, {'_id': 0}).sort('created_at', -1).skip((page - 1) * per_page).limit(per_page))
        return jsonify({
            'scans': scans, 'total': total, 'page': page, 'per_page': per_page, 
            'total_pages': (total + per_page - 1) // per_page if per_page > 0 else 1
        })
    except Exception as e:
        logger.error(f"Error loading history: {e}")
        return jsonify({'error': 'Database error fetching history'}), 500

@app.route('/api/delete_scan/<scan_id>', methods=['DELETE'])
@login_required
def delete_scan(scan_id):
    safe_scan_id = secure_filename(scan_id)
    try:
        db.scans.delete_one({'scan_id': safe_scan_id})
        shutil.rmtree(f'scans/{safe_scan_id}', ignore_errors=True)
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error deleting scan {safe_scan_id}: {e}")
        return jsonify({'error': 'Failed to delete scan'}), 500

@app.route('/api/scan_files/<scan_id>', methods=['GET'])
@login_required
def get_scan_files(scan_id):
    safe_scan_id = secure_filename(scan_id)
    scan_dir = Path(f'scans/{safe_scan_id}')
    if not scan_dir.exists(): 
        return jsonify([])
    try:
        files = sorted([f.name for f in scan_dir.rglob('*') if f.is_file() and not f.name.endswith('.sqlite3')])
        return jsonify(files)
    except Exception as e:
        logger.error(f"Error listing files for {safe_scan_id}: {e}")
        return jsonify({'error': 'Failed to list files'}), 500

@app.route('/api/view_file/<scan_id>/<path:filename>', methods=['GET'])
@login_required
def read_scan_file(scan_id, filename):
    try:
        safe_scan_id = secure_filename(scan_id)
        # Using path to handle possible subdirectories (e.g., screenshots), but enforce sandbox
        scan_dir = Path(f'scans/{safe_scan_id}').resolve()
        safe_path = (scan_dir / filename).resolve()
        
        # Strict Path traversal prevention
        if not safe_path.is_relative_to(scan_dir):
            abort(403, description="Access Denied: Path traversal detected")

        if not safe_path.exists() or not safe_path.is_file():
            abort(404, description="File not found")

        content = safe_path.read_text(encoding='utf-8', errors='replace')

        if filename.endswith(('.json', '.jsonl')):
            pretty_content = ""
            try:
                if filename.endswith('.jsonl'):
                    lines = content.strip().split('\n')
                    json_objects = [json.loads(line) for line in lines if line.strip()]
                    pretty_content = json.dumps(json_objects, indent=4)
                else:
                    data = json.loads(content)
                    pretty_content = json.dumps(data, indent=4)
                return pretty_content
            except (json.JSONDecodeError, TypeError):
                return content 
        
        return content
    except FileNotFoundError:
        return "File not found.", 404
    except Exception as e:
        logger.error(f"Error reading file {filename} for {scan_id}: {e}")
        return "Error reading file", 500

@app.route('/export_csv/<scan_id>')
@login_required
def export_csv(scan_id):
    safe_scan_id = secure_filename(scan_id)
    scan_dir = Path(f'scans/{safe_scan_id}')
    if not scan_dir.exists(): 
        return jsonify({'error': 'Not found'}), 404
        
    try:
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(['Module', 'Severity', 'Finding', 'Target/Endpoint'])
        
        nuclei_file = scan_dir / 'nuclei.jsonl'
        if nuclei_file.exists():
            for line in parse_json_lines_helper(nuclei_file):
                info = line.get('info', {})
                cw.writerow(['nuclei', info.get('severity', 'N/A'), info.get('name', 'N/A'), line.get('matched-at', '')])

        output = io.BytesIO(si.getvalue().encode('utf-8'))
        output.seek(0)
        return send_file(output, as_attachment=True, download_name=f'scan_summary_{safe_scan_id}.csv', mimetype='text/csv')
    except Exception as e:
        logger.error(f"Error exporting CSV for {safe_scan_id}: {e}")
        return jsonify({'error': 'Failed to generate CSV'}), 500

if __name__ == '__main__':
    logger.info("Initializing application dependencies...")
    check_dependencies()
    
    # Start background scheduler for user-defined pipeline scans
    scheduler_thread = threading.Thread(target=scheduler_loop, daemon=True)
    scheduler_thread.start()
    
    # Start 4-hour periodic continuous subfinder monitor
    subfinder_monitor_thread = threading.Thread(target=continuous_subfinder_monitor, daemon=True)
    subfinder_monitor_thread.start()
    
    logger.info("Starting web server on port 5000...")
    # NOTE: Using allow_unsafe_werkzeug to maintain original socket.io requirements without gevent monkey-patching,
    # but for true strict production, it's advised to serve this behind Gunicorn + Eventlet.
    socketio.run(app, debug=False, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)), allow_unsafe_werkzeug=True)
