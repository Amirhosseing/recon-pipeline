import os
import json
import tempfile
import subprocess
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

from extensions import db, scan_queue
from config import logger, REQUIRED_TOOLS
from utils import get_tool_path, generate_unique_scan_id
from telegram import send_telegram_alert
from core.scanner import ScanRunner


# --- Scheduler Logic ---
def scheduler_loop():
    """Background thread to dispatch scheduled and recurring scans."""
    logger.info("⏰ Scheduler thread started successfully.")
    while True:
        try:
            if db is None:
                logger.warning("Scheduler: MongoDB not available, skipping cycle.")
                time.sleep(10)
                continue
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
            if db is None:
                logger.warning("Monitor: MongoDB not available, sleeping.")
                time.sleep(14400)
                continue
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

