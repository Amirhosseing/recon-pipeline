import os
import json
import functools
import shutil
from pathlib import Path
from typing import List, Dict

from config import logger, REQUIRED_TOOLS


# --- Smart Binary Resolver ---
@functools.lru_cache(maxsize=32)
def get_tool_path(tool_name: str) -> str:
    """Resolves the absolute path to a tool binary, with caching for performance."""
    path = shutil.which(tool_name)
    if path:
        return path

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
        logger.warning(f"MISSING TOOLS DETECTED: {', '.join(missing)}. Some pipeline stages will fail.")
    else:
        logger.info("All required tools are installed and accessible.")


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
            for _ in f:
                count += 1
    except Exception as e:
        logger.error(f"Error counting lines for {file_path}: {e}")
    return count


def generate_unique_scan_id() -> str:
    """Generates a unique scan ID using timestamp + short UUID to avoid collisions."""
    from datetime import datetime
    import uuid
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    short_uuid = uuid.uuid4().hex[:6]
    return f"{timestamp}_{short_uuid}"
