import threading

from extensions import app, socketio, logger
from utils import check_dependencies
from core.background import scheduler_loop, continuous_subfinder_monitor

# Import routes to register them with the Flask app
from routes import all_routes


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
    socketio.run(app, debug=False, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
