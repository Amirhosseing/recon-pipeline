import os
import logging
from flask.json.provider import DefaultJSONProvider
from bson import ObjectId
from datetime import datetime
from typing import Any

# --- Configuration & Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(name)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("ReconPipeline")

# Credentials
ADMIN_USERNAME = os.environ.get('ADMIN_USER', 'administrator')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASS', 'Qwer12#$')
if ADMIN_PASSWORD == 'Qwer12#$':
    logger.warning("SECURITY WARNING: Running with default ADMIN_PASSWORD. Please set ADMIN_PASS environment variable in production.")

# MongoDB Config
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = os.environ.get("DB_NAME", "recon_pipeline")

# Tool Configuration
REQUIRED_TOOLS = ['subfinder', 'puredns', 'dnsx', 'cdncheck', 'tlsx', 'httpx', 'katana', 'nmap', 'nuclei', 'ffuf', 'gowitness']

# Telegram Config - MUST be set via environment variables
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')

# Validate Telegram config
if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
    logger.warning("Telegram notifications disabled: TELEGRAM_BOT_TOKEN and/or TELEGRAM_CHAT_ID not set.")

# LLM Config (OpenAI-compatible API — Ollama, LM Studio, vLLM, Together, etc.)
LLM_API_KEY = os.environ.get('LLM_API_KEY', '')
LLM_BASE_URL = os.environ.get('LLM_BASE_URL', 'http://host.docker.internal:11434/v1')
LLM_MODEL = os.environ.get('LLM_MODEL', 'qwen3:8b')

# AI Analysis output schema — defines the structure the LLM must return
ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "executive_summary": {"type": "string", "description": "2-3 sentence overview of attack surface and key risks"},
        "risk_level": {"type": "string", "enum": ["critical", "high", "medium", "low"], "description": "Overall risk rating"},
        "risk_justification": {"type": "string", "description": "Why this risk level was assigned"},
        "attack_surface": {
            "type": "object",
            "properties": {
                "subdomains": {"type": "integer"},
                "live_urls": {"type": "integer"},
                "open_ports": {"type": "integer"},
                "vulnerabilities": {"type": "integer"},
                "unique_ips": {"type": "integer"}
            },
            "required": ["subdomains", "live_urls", "open_ports", "vulnerabilities", "unique_ips"]
        },
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    "category": {"type": "string"},
                    "description": {"type": "string"},
                    "evidence": {"type": "string"},
                    "source_tool": {"type": "string"}
                },
                "required": ["severity", "category", "description", "evidence", "source_tool"]
            }
        },
        "recommendations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "priority": {"type": "string", "enum": ["immediate", "short_term", "long_term"]},
                    "action": {"type": "string"},
                    "rationale": {"type": "string"}
                },
                "required": ["priority", "action", "rationale"]
            }
        }
    },
    "required": ["executive_summary", "risk_level", "risk_justification", "attack_surface", "findings", "recommendations"]
}


# Custom JSON Provider for MongoDB ObjectIds and Datetimes
class MongoJSONProvider(DefaultJSONProvider):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, ObjectId):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)
