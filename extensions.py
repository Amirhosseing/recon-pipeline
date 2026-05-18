from flask import Flask
from flask_socketio import SocketIO
from pymongo import MongoClient, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

from config import logger, MONGO_URI, DB_NAME, MongoJSONProvider

app = Flask(__name__)
# WARNING: In production, SECRET_KEY must be injected via environment variables.
import os
app.secret_key = os.environ.get('SECRET_KEY', 'super_secret_key_change_in_prod')
if app.secret_key == 'super_secret_key_change_in_prod':
    logger.warning("SECURITY WARNING: Running with default SECRET_KEY. Please set SECRET_KEY environment variable in production.")

app.json = MongoJSONProvider(app)

socketio = SocketIO(app, cors_allowed_origins="*")

# Globals
scan_queue = {}
db = None
mongo_client = None

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

    logger.info("Successfully connected to MongoDB")

    # Fix stuck scans on restart
    result = db.scans.update_many(
        {'status': 'running'},
        {'$set': {'status': 'interrupted', 'error': 'Server restarted during scan'}}
    )
    if result.modified_count > 0:
        logger.info(f"Reset {result.modified_count} stuck scans to 'interrupted' state.")
except (ConnectionFailure, ServerSelectionTimeoutError) as e:
    logger.critical(f"Failed to connect to MongoDB: {e}")
    # In a strict production environment, we might sys.exit(1) here.
except Exception as e:
    logger.critical(f"Unexpected database initialization error: {e}")
