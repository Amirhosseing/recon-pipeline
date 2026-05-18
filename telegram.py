import config
import os
import time
from typing import Optional

import requests

from config import logger


# --- TELEGRAM HELPER ---
def send_telegram_alert(message: str) -> bool:
    """Sends a Telegram alert. Returns False if not configured or on error."""
    if not config.TELEGRAM_BOT_TOKEN or not config.TELEGRAM_CHAT_ID:
        logger.debug("Telegram not configured, skipping alert.")
        return False

    proxies = {"http": "socks5://host.docker.internal:10808", "https": "socks5://host.docker.internal:10808"}
    url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": config.TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}

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
    if not config.TELEGRAM_BOT_TOKEN or not config.TELEGRAM_CHAT_ID:
        return False
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        return False

    # Validate token format (basic check)
    if not config.TELEGRAM_BOT_TOKEN.count(':') >= 1 or len(config.TELEGRAM_BOT_TOKEN) < 40:
        logger.warning("Invalid Telegram bot token format, skipping document upload.")
        return False

    proxies = {"http": "socks5://host.docker.internal:10808", "https": "socks5://host.docker.internal:10808"}
    url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendDocument"
    data = {"chat_id": config.TELEGRAM_CHAT_ID}
    if caption:
        data["caption"] = caption

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
