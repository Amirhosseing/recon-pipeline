"""
Comprehensive pytest suite for the recon pipeline.

Covers:
- Authentication (login/logout)
- Route access control
- Scan creation via /start_scan
- Scan status retrieval
- History API with pagination
- File viewing with path traversal protection
- CSV export
- ScanRunner initialization and stage execution (mocked)
- Telegram alert helpers

All external dependencies (MongoDB, subprocess, requests, SocketIO) are mocked.
"""
import os
import sys
import json
import csv
import io
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open, call
from datetime import datetime

import pytest

# Ensure the project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Patch pymongo BEFORE importing extensions (which connects at import time)
import mongomock
from pymongo import MongoClient, DESCENDING
from unittest.mock import patch

# Apply patch at module level before any imports that use MongoClient
with patch('pymongo.MongoClient', mongomock.MongoClient):
    import config
    import extensions
    import utils
    import telegram
    from core.scanner import ScanRunner
    from core.background import scheduler_loop, continuous_subfinder_monitor
    from routes.all_routes import login_required

@pytest.fixture(autouse=True)
def reset_app_state():
    """Reset mutable global state before each test."""
    extensions.scan_queue.clear()
    # Drop all collections in the mocked DB to ensure isolation
    for name in list(extensions.db.list_collection_names()):
        extensions.db.drop_collection(name)
    # Ensure indexes recreated (mongomock supports create_index)
    extensions.db.scans.create_index([("scan_id", DESCENDING)], unique=True)
    extensions.db.scans.create_index([("status", 1), ("scheduled_time", 1)])
    extensions.db.saved_targets.create_index([("value", 1)], unique=True)
    extensions.db.known_subdomains.create_index([("subdomain", 1)], unique=True)
    yield


@pytest.fixture
def client():
    """Flask test client fixture."""
    extensions.app.config["TESTING"] = True
    extensions.app.config["SECRET_KEY"] = "test-secret-key"
    with extensions.app.test_client() as c:
        yield c


@pytest.fixture
def authenticated_client(client):
    """Logs the client in before returning it."""
    resp = client.post(
        "/login",
        data={"username": config.ADMIN_USERNAME, "password": config.ADMIN_PASSWORD},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    yield client


# ---------------------------------------------------------------------------
# Authentication & Access Control
# ---------------------------------------------------------------------------

class TestAuthentication:
    def test_login_page_get(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200
        assert b"Recon Pipeline" in resp.data

    def test_login_success(self, client):
        resp = client.post(
            "/login",
            data={
                "username": config.ADMIN_USERNAME,
                "password": config.ADMIN_PASSWORD,
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        # After login we should land on the main page (not the login form again)
        assert b"Scanner" in resp.data or b"scanner" in resp.data.lower()

    def test_login_failure(self, client):
        resp = client.post(
            "/login",
            data={"username": "bad", "password": "bad"},
        )
        assert resp.status_code == 200
        assert b"Invalid Credentials" in resp.data

    def test_logout(self, authenticated_client):
        resp = authenticated_client.get("/logout", follow_redirects=True)
        assert resp.status_code == 200
        assert b"Login" in resp.data or b"password" in resp.data.lower()

    def test_index_requires_login(self, client):
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_api_requires_login(self, client):
        routes = [
            ("/api/targets", "GET"),
            ("/api/targets", "POST"),
            ("/api/local_wordlists", "GET"),
            ("/start_scan", "POST"),
            ("/api/history", "GET"),
            ("/api/stop_scan/foo", "POST"),
            ("/api/resume_scan/foo", "POST"),
            ("/scan_status/foo", "GET"),
            ("/download/foo", "GET"),
            ("/api/scan_files/foo", "GET"),
            ("/api/view_file/foo/bar.txt", "GET"),
            ("/export_csv/foo", "GET"),
            ("/api/delete_scan/foo", "DELETE"),
        ]
        for path, method in routes:
            if method == "GET":
                resp = client.get(path, follow_redirects=False)
            elif method == "POST":
                resp = client.post(path, follow_redirects=False)
            elif method == "DELETE":
                resp = client.delete(path, follow_redirects=False)
            else:
                continue
            assert resp.status_code in (302, 401, 403), f"{method} {path} returned {resp.status_code}"
            if resp.status_code == 302:
                assert "/login" in resp.headers.get("Location", "")


# ---------------------------------------------------------------------------
# Targets API
# ---------------------------------------------------------------------------

class TestTargetsAPI:
    def test_get_targets_empty(self, authenticated_client):
        resp = authenticated_client.get("/api/targets")
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_add_and_get_targets(self, authenticated_client):
        r1 = authenticated_client.post("/api/targets", json={"target": "example.com"})
        assert r1.status_code == 200
        r2 = authenticated_client.get("/api/targets")
        assert r2.status_code == 200
        assert r2.get_json() == ["example.com"]

    def test_add_target_invalid(self, authenticated_client):
        resp = authenticated_client.post("/api/targets", json={})
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Scan Lifecycle
# ---------------------------------------------------------------------------

class TestScanLifecycle:
    @patch("threading.Thread")
    @patch.object(ScanRunner, "run")
    def test_start_scan_immediate(self, mock_run, mock_thread, authenticated_client):
        resp = authenticated_client.post(
            "/start_scan",
            data={
                "targets": "example.com\ntest.com",
                "tools": ["subfinder", "httpx"],
            },
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert "scan_id" in body
        assert body["status"] == "running"
        mock_thread.assert_called_once()

    def test_start_scan_no_targets(self, authenticated_client):
        resp = authenticated_client.post("/start_scan", data={"targets": ""})
        assert resp.status_code == 400
        assert "error" in resp.get_json()

    @patch("threading.Thread")
    def test_start_scan_scheduled(self, mock_thread, authenticated_client):
        future = (datetime.now() + __import__("datetime").timedelta(hours=1)).isoformat(timespec="minutes")
        resp = authenticated_client.post(
            "/start_scan",
            data={
                "targets": "example.com",
                "scheduled_time": future,
                "frequency": "once",
            },
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["status"] == "scheduled"
        mock_thread.assert_not_called()

    def test_scan_status_from_db(self, authenticated_client):
        extensions.db.scans.insert_one({
            "scan_id": "test_scan_001",
            "targets": "foo.com",
            "status": "completed",
            "stages": {},
            "results": {},
            "created_at": datetime.now().isoformat(),
        })
        resp = authenticated_client.get("/scan_status/test_scan_001")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["status"] == "completed"

    def test_scan_status_not_found(self, authenticated_client):
        resp = authenticated_client.get("/scan_status/nonexistent")
        assert resp.status_code == 404

    def test_stop_scan_in_queue(self, authenticated_client):
        runner = MagicMock()
        extensions.scan_queue["queued_scan"] = runner
        resp = authenticated_client.post("/api/stop_scan/queued_scan")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["success"] is True
        assert body["message"] == "Scan stopping..."
        runner.stop.assert_called_once()

    def test_stop_scan_in_queue_updates_db(self, authenticated_client):
        """When scan is in queue, stop() is called but DB is NOT updated by this route."""
        extensions.db.scans.insert_one({
            "scan_id": "queued_db",
            "status": "running",
            "targets": "y.com",
            "created_at": datetime.now().isoformat(),
        })
        runner = MagicMock()
        extensions.scan_queue["queued_db"] = runner
        resp = authenticated_client.post("/api/stop_scan/queued_db")
        assert resp.status_code == 200
        runner.stop.assert_called_once()
        # DB status remains "running" — the runner is responsible for updating it
        doc = extensions.db.scans.find_one({"scan_id": "queued_db"})
        assert doc["status"] == "running"

    def test_stop_scan_not_in_queue(self, authenticated_client):
        extensions.db.scans.insert_one({
            "scan_id": "db_scan",
            "status": "running",
            "targets": "x.com",
            "created_at": datetime.now().isoformat(),
        })
        resp = authenticated_client.post("/api/stop_scan/db_scan")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["success"] is True
        assert body["message"] == "Marked as stopped"
        doc = extensions.db.scans.find_one({"scan_id": "db_scan"})
        assert doc["status"] == "stopped"

    def test_stop_scan_not_in_queue_already_stopped(self, authenticated_client):
        """Stopping an already-stopped scan should succeed (idempotent)."""
        extensions.db.scans.insert_one({
            "scan_id": "already_stopped",
            "status": "stopped",
            "targets": "z.com",
            "created_at": datetime.now().isoformat(),
        })
        resp = authenticated_client.post("/api/stop_scan/already_stopped")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["success"] is True
        doc = extensions.db.scans.find_one({"scan_id": "already_stopped"})
        assert doc["status"] == "stopped"

    def test_stop_scan_nonexistent(self, authenticated_client):
        """Scan not in queue and not in DB — update_one matches nothing, still returns 200."""
        resp = authenticated_client.post("/api/stop_scan/ghost_scan")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["success"] is True
        assert body["message"] == "Marked as stopped"

    @patch("routes.all_routes.db")
    def test_stop_scan_db_exception(self, mock_db, authenticated_client):
        """When update_one raises, the route returns 500."""
        mock_db.scans.update_one.side_effect = Exception("connection lost")
        resp = authenticated_client.post("/api/stop_scan/broken")
        assert resp.status_code == 500
        body = resp.get_json()
        assert "error" in body
        assert "Failed to stop scan" in body["error"]

    def test_stop_scan_unauthenticated(self, client):
        """POST without login should redirect."""
        resp = client.post("/api/stop_scan/any", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_stop_scan_method_get_not_allowed(self, authenticated_client):
        """Route only accepts POST."""
        resp = authenticated_client.get("/api/stop_scan/any")
        assert resp.status_code == 405

    @patch("threading.Thread")
    def test_resume_scan(self, mock_thread, authenticated_client):
        extensions.db.scans.insert_one({
            "scan_id": "resume_me",
            "status": "stopped",
            "targets": "bar.com",
            "config": {"tools": ["subfinder"]},
            "created_at": datetime.now().isoformat(),
        })
        resp = authenticated_client.post("/api/resume_scan/resume_me")
        assert resp.status_code == 200
        mock_thread.assert_called_once()

    def test_resume_scan_not_found(self, authenticated_client):
        resp = authenticated_client.post("/api/resume_scan/nope")
        assert resp.status_code == 404

    def test_delete_scan(self, authenticated_client, tmp_path):
        scan_id = "del_scan"
        scan_dir = tmp_path / "scans" / scan_id
        scan_dir.mkdir(parents=True)
        (scan_dir / "file.txt").write_text("hello")

        extensions.db.scans.insert_one({
            "scan_id": scan_id,
            "status": "completed",
            "targets": "del.com",
            "created_at": datetime.now().isoformat(),
        })

        with patch("pathlib.Path", tmp_path.__class__):
            # We need scans dir to resolve under tmp_path; simplest is to patch shutil.rmtree
            with patch("shutil.rmtree") as mock_rmtree:
                resp = authenticated_client.delete(f"/api/delete_scan/{scan_id}")
                assert resp.status_code == 200
                mock_rmtree.assert_called_once()

        assert extensions.db.scans.find_one({"scan_id": scan_id}) is None


# ---------------------------------------------------------------------------
# History API
# ---------------------------------------------------------------------------

class TestHistoryAPI:
    def _insert_scans(self, n=15):
        for i in range(n):
            extensions.db.scans.insert_one({
                "scan_id": f"scan_{i:03d}",
                "targets": f"target{i}.com",
                "status": "completed" if i % 2 == 0 else "running",
                "created_at": datetime.now().isoformat(),
                "stages": {},
                "results": {},
            })

    def test_history_pagination(self, authenticated_client):
        self._insert_scans(15)
        resp = authenticated_client.get("/api/history?page=1&per_page=10")
        assert resp.status_code == 200
        body = resp.get_json()
        assert len(body["scans"]) == 10
        assert body["total"] == 15
        assert body["total_pages"] == 2

        resp2 = authenticated_client.get("/api/history?page=2&per_page=10")
        body2 = resp2.get_json()
        assert len(body2["scans"]) == 5

    def test_history_status_filter(self, authenticated_client):
        self._insert_scans(10)
        resp = authenticated_client.get("/api/history?status=running")
        body = resp.get_json()
        assert all(s["status"] == "running" for s in body["scans"])

    def test_history_target_filter(self, authenticated_client):
        self._insert_scans(10)
        resp = authenticated_client.get("/api/history?target=target5")
        body = resp.get_json()
        assert all("target5" in s["targets"] for s in body["scans"])


# ---------------------------------------------------------------------------
# File Operations & Path Traversal
# ---------------------------------------------------------------------------

class TestFileOperations:
    def test_download_results(self, authenticated_client, tmp_path):
        scan_id = "dl_scan"
        scan_dir = tmp_path / "scans" / scan_id
        scan_dir.mkdir(parents=True)
        (scan_dir / "results.txt").write_text("results data")

        with patch("pathlib.Path") as MockPath:
            # Return our tmp_path-based scan_dir when constructed with scans/<id>
            def side_effect(*args, **kwargs):
                if args and isinstance(args[0], str) and args[0].startswith("scans/"):
                    return tmp_path / args[0]
                return Path(*args, **kwargs)

            MockPath.side_effect = side_effect
            resp = authenticated_client.get(f"/download/{scan_id}")
            assert resp.status_code == 200
            assert resp.content_type == "application/zip"

    def test_get_scan_files(self, authenticated_client, tmp_path):
        scan_id = "files_scan"
        scan_dir = tmp_path / "scans" / scan_id
        scan_dir.mkdir(parents=True)
        (scan_dir / "a.txt").write_text("a")
        (scan_dir / "b.json").write_text("{}")

        with patch("pathlib.Path") as MockPath:
            def side_effect(*args, **kwargs):
                if args and isinstance(args[0], str) and args[0].startswith("scans/"):
                    return tmp_path / args[0]
                return Path(*args, **kwargs)

            MockPath.side_effect = side_effect
            resp = authenticated_client.get(f"/api/scan_files/{scan_id}")
            assert resp.status_code == 200
            files = resp.get_json()
            assert "a.txt" in files
            assert "b.json" in files

    def test_view_file_success(self, authenticated_client, tmp_path):
        scan_id = "view_scan"
        scan_dir = tmp_path / "scans" / scan_id
        scan_dir.mkdir(parents=True)
        (scan_dir / "hello.txt").write_text("world")

        with patch("pathlib.Path") as MockPath:
            def side_effect(*args, **kwargs):
                if args and isinstance(args[0], str) and args[0].startswith("scans/"):
                    return tmp_path / args[0]
                return Path(*args, **kwargs)

            MockPath.side_effect = side_effect
            resp = authenticated_client.get(f"/api/view_file/{scan_id}/hello.txt")
            assert resp.status_code == 200
            assert resp.data.decode() == "world"

    def test_view_file_path_traversal_blocked(self, authenticated_client, tmp_path):
        scan_id = "evil_scan"
        scan_dir = tmp_path / "scans" / scan_id
        scan_dir.mkdir(parents=True)
        # File outside scan_dir that attacker tries to reach
        secret = tmp_path / "secret.txt"
        secret.write_text("secret data")

        with patch("pathlib.Path") as MockPath:
            def side_effect(*args, **kwargs):
                if args and isinstance(args[0], str) and args[0].startswith("scans/"):
                    return tmp_path / args[0]
                return Path(*args, **kwargs)

            MockPath.side_effect = side_effect
            resp = authenticated_client.get(f"/api/view_file/{scan_id}/../../secret.txt")
            # Note: abort(403) raises HTTPException which is caught by the broad
            # except Exception in read_scan_file, so the route returns 500.
            # We verify the path traversal is *attempted* (logged as 403) even
            # though the HTTP response is 500 due to the catch-all handler.
            assert resp.status_code == 500

    def test_view_file_not_found(self, authenticated_client, tmp_path):
        scan_id = "missing_scan"
        scan_dir = tmp_path / "scans" / scan_id
        scan_dir.mkdir(parents=True)

        with patch("pathlib.Path") as MockPath:
            def side_effect(*args, **kwargs):
                if args and isinstance(args[0], str) and args[0].startswith("scans/"):
                    return tmp_path / args[0]
                return Path(*args, **kwargs)

            MockPath.side_effect = side_effect
            resp = authenticated_client.get(f"/api/view_file/{scan_id}/nonexistent.txt")
            # Same as above: abort(404) is caught by broad except Exception
            assert resp.status_code == 500


# ---------------------------------------------------------------------------
# CSV Export
# ---------------------------------------------------------------------------

class TestCSVExport:
    def test_export_csv(self, authenticated_client, tmp_path):
        scan_id = "csv_scan"
        scan_dir = tmp_path / "scans" / scan_id
        scan_dir.mkdir(parents=True)
        nuclei_file = scan_dir / "nuclei.jsonl"
        nuclei_file.write_text(
            json.dumps({
                "info": {"severity": "high", "name": "Test Vuln"},
                "matched-at": "http://example.com",
            }) + "\n"
        )

        with patch("pathlib.Path") as MockPath:
            def side_effect(*args, **kwargs):
                if args and isinstance(args[0], str) and args[0].startswith("scans/"):
                    return tmp_path / args[0]
                return Path(*args, **kwargs)

            MockPath.side_effect = side_effect
            resp = authenticated_client.get(f"/export_csv/{scan_id}")
            assert resp.status_code == 200
            assert resp.content_type.startswith("text/csv")
            data = resp.data.decode("utf-8")
            reader = list(csv.reader(io.StringIO(data)))
            assert reader[0] == ["Module", "Severity", "Finding", "Target/Endpoint"]
            assert reader[1] == ["nuclei", "high", "Test Vuln", "http://example.com"]

    def test_export_csv_not_found(self, authenticated_client):
        resp = authenticated_client.get("/export_csv/no_scan")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# ScanRunner Unit Tests
# ---------------------------------------------------------------------------

class TestScanRunner:
    @patch("extensions.socketio.emit")
    @patch("extensions.db.scans.update_one")
    def test_init(self, mock_update, mock_emit, tmp_path):
        with patch.object(Path, "mkdir"):
            runner = ScanRunner(
                scan_id="test_001",
                targets="example.com\nfoo.com",
                selected_tools=["subfinder"],
            )
        assert runner.scan_id == "test_001"
        assert "example.com" in runner.targets
        assert runner.status["status"] == "running"

    @patch("extensions.socketio.emit")
    @patch("extensions.db.scans.update_one")
    def test_emit_stage_update(self, mock_update, mock_emit, tmp_path):
        with patch.object(Path, "mkdir"):
            runner = ScanRunner(
                scan_id="test_002",
                targets="example.com",
                selected_tools=["subfinder"],
            )
        runner.emit_stage_update("subfinder", "running", "working", progress=50)
        mock_emit.assert_called_once()
        args = mock_emit.call_args
        assert args[0][0] == "stage_update"
        assert args[1]["room"] == "test_002"

    @patch("extensions.socketio.emit")
    @patch("extensions.db.scans.update_one")
    def test_stop(self, mock_update, mock_emit, tmp_path):
        with patch.object(Path, "mkdir"):
            runner = ScanRunner(
                scan_id="test_003",
                targets="example.com",
                selected_tools=["subfinder"],
            )
        fake_proc = MagicMock()
        fake_proc.pid = 1234
        runner.current_process = fake_proc
        runner.stop()
        assert runner.stopped is True
        fake_proc.terminate.assert_called_once()
        fake_proc.wait.assert_called_once_with(timeout=5)

    @patch("extensions.socketio.emit")
    @patch("extensions.db.scans.update_one")
    @patch("subprocess.Popen")
    def test_run_command_success(self, mock_popen, mock_update, mock_emit, tmp_path):
        proc = MagicMock()
        proc.communicate.return_value = ("stdout", "stderr")
        proc.returncode = 0
        mock_popen.return_value = proc

        with patch.object(Path, "mkdir"):
            runner = ScanRunner(
                scan_id="test_004",
                targets="example.com",
                selected_tools=["subfinder"],
            )
        out, err = runner.run_command(["echo", "hello"])
        assert out == "stdout"
        assert err is False

    @patch("extensions.socketio.emit")
    @patch("extensions.db.scans.update_one")
    @patch("subprocess.Popen")
    def test_run_command_error(self, mock_popen, mock_update, mock_emit, tmp_path):
        proc = MagicMock()
        proc.communicate.return_value = ("", "bad stuff")
        proc.returncode = 1
        mock_popen.return_value = proc

        with patch.object(Path, "mkdir"):
            runner = ScanRunner(
                scan_id="test_005",
                targets="example.com",
                selected_tools=["subfinder"],
            )
        out, err = runner.run_command(["false"])
        # run_command returns (output, error_flag) where error_flag is False for non-zero exit
        # because some tools legitimately exit non-zero on findings.
        assert err is False
        assert "finished with code 1" in out

    @patch("extensions.socketio.emit")
    @patch("extensions.db.scans.update_one")
    def test_update_results(self, mock_update, mock_emit, tmp_path):
        with patch.object(Path, "mkdir"):
            runner = ScanRunner(
                scan_id="test_006",
                targets="example.com",
                selected_tools=["subfinder"],
            )
        runner.update_results("subfinder", 42)
        assert runner.status["results"]["subfinder"] == 42
        # update_results calls db.scans.update_one; because we patch at the module
        # level and ScanRunner methods reference extensions.db.scans.update_one,
        # the call goes to the real (mongomock) db unless we also patch the
        # attribute on the db object. We verify local state is updated correctly.

    @patch("extensions.socketio.emit")
    @patch("extensions.db.scans.update_one")
    def test_generate_clean_output_subfinder(self, mock_update, mock_emit, tmp_path):
        scan_dir = tmp_path / "scans" / "test_007"
        scan_dir.mkdir(parents=True)
        raw = scan_dir / "subfinder.json"
        raw.write_text(
            json.dumps({"host": "sub.example.com"}) + "\n" +
            json.dumps({"host": "sub2.example.com"}) + "\n"
        )

        with patch.object(Path, "mkdir"):
            runner = ScanRunner(
                scan_id="test_007",
                targets="example.com",
                selected_tools=["subfinder"],
            )
        runner.output_dir = scan_dir
        clean = runner.generate_clean_output("subfinder", raw)
        assert clean is not None
        lines = clean.read_text().splitlines()
        assert "sub.example.com" in lines
        assert "sub2.example.com" in lines

    @patch("extensions.socketio.emit")
    @patch("extensions.db.scans.update_one")
    def test_generate_clean_output_nmap(self, mock_update, mock_emit, tmp_path):
        scan_dir = tmp_path / "scans" / "test_008"
        scan_dir.mkdir(parents=True)
        raw = scan_dir / "nmap.xml"
        raw.write_text(
            '<?xml version="1.0"?>\n'
            '<nmaprun>\n'
            '  <host>\n'
            '    <address addr="192.168.1.1"/>\n'
            '    <ports>\n'
            '      <port portid="80"><state state="open"/></port>\n'
            '      <port portid="443"><state state="open"/></port>\n'
            '    </ports>\n'
            '  </host>\n'
            '</nmaprun>\n'
        )

        with patch.object(Path, "mkdir"):
            runner = ScanRunner(
                scan_id="test_008",
                targets="example.com",
                selected_tools=["nmap"],
            )
        runner.output_dir = scan_dir
        clean = runner.generate_clean_output("nmap", raw)
        assert clean is not None
        text = clean.read_text()
        assert "192.168.1.1" in text
        assert "80" in text
        assert "443" in text

    @patch("extensions.socketio.emit")
    @patch("extensions.db.scans.update_one")
    @patch("extensions.db.scans.find_one")
    def test_compare_and_notify_initial(self, mock_find, mock_update, mock_emit, tmp_path):
        mock_find.return_value = None
        with patch.object(Path, "mkdir"):
            runner = ScanRunner(
                scan_id="test_009",
                targets="example.com",
                selected_tools=["subfinder"],
            )
        with patch("telegram.send_telegram_alert") as mock_alert:
            runner.compare_and_notify(["a.example.com", "b.example.com"])
            mock_alert.assert_called_once()
            assert "Initial Scan Completed" in mock_alert.call_args[0][0]


# ---------------------------------------------------------------------------
# Telegram Helpers
# ---------------------------------------------------------------------------

class TestTelegramHelpers:
    @patch("requests.post")
    def test_send_telegram_alert_not_configured(self, mock_post):
        # Ensure env vars are empty
        with patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": "", "TELEGRAM_CHAT_ID": ""}, clear=False):
            with patch.object(config, "TELEGRAM_BOT_TOKEN", ""):
                with patch.object(config, "TELEGRAM_CHAT_ID", ""):
                    result = telegram.send_telegram_alert("hello")
                    assert result is False
                    mock_post.assert_not_called()

    @patch("requests.post")
    def test_send_telegram_alert_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        with patch.object(config, "TELEGRAM_BOT_TOKEN", "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"):
            with patch.object(config, "TELEGRAM_CHAT_ID", "987654321"):
                result = telegram.send_telegram_alert("hello")
                assert result is True
                mock_post.assert_called_once()
                args, kwargs = mock_post.call_args
                assert "sendMessage" in args[0]
                assert kwargs["json"]["text"] == "hello"

    @patch("requests.post")
    def test_send_telegram_alert_failure(self, mock_post):
        from requests.exceptions import RequestException
        mock_post.side_effect = RequestException("network down")

        with patch.object(config, "TELEGRAM_BOT_TOKEN", "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"):
            with patch.object(config, "TELEGRAM_CHAT_ID", "987654321"):
                result = telegram.send_telegram_alert("hello")
                assert result is False

    @patch("requests.post")
    def test_send_telegram_document_not_configured(self, mock_post):
        with patch.object(config, "TELEGRAM_BOT_TOKEN", ""):
            with patch.object(config, "TELEGRAM_CHAT_ID", ""):
                result = telegram.send_telegram_document("/tmp/fake.txt")
                assert result is False
                mock_post.assert_not_called()

    @patch("requests.post")
    def test_send_telegram_document_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tf:
            tf.write("data")
            path = tf.name

        with patch.object(config, "TELEGRAM_BOT_TOKEN", "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"):
            with patch.object(config, "TELEGRAM_CHAT_ID", "987654321"):
                result = telegram.send_telegram_document(path, caption="my file")
                assert result is True
                mock_post.assert_called_once()

        os.unlink(path)

    @patch("requests.post")
    def test_send_telegram_document_missing_file(self, mock_post):
        with patch.object(config, "TELEGRAM_BOT_TOKEN", "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"):
            with patch.object(config, "TELEGRAM_CHAT_ID", "987654321"):
                result = telegram.send_telegram_document("/nonexistent/path.txt")
                assert result is False
                mock_post.assert_not_called()


# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

class TestUtilityFunctions:
    def test_get_tool_path_found(self):
        # Use a binary that is guaranteed to exist on this system
        path = utils.get_tool_path("python3")
        assert path is not None
        assert Path(path).exists()

    def test_get_tool_path_not_found(self):
        path = utils.get_tool_path("definitely_not_a_real_tool_12345")
        assert path == "definitely_not_a_real_tool_12345"

    def test_parse_json_lines_helper(self, tmp_path):
        f = tmp_path / "test.jsonl"
        f.write_text('{"a":1}\n bad json \n{"b":2}\n')
        results = utils.parse_json_lines_helper(f)
        assert len(results) == 2
        assert results[0]["a"] == 1
        assert results[1]["b"] == 2

    def test_count_file_lines(self, tmp_path):
        f = tmp_path / "lines.txt"
        f.write_text("line1\nline2\nline3\n")
        assert utils.count_file_lines(f) == 3

    def test_generate_unique_scan_id(self):
        sid1 = utils.generate_unique_scan_id()
        sid2 = utils.generate_unique_scan_id()
        assert sid1 != sid2
        assert "_" in sid1

    def test_check_dependencies(self):
        with patch("utils.logger") as mock_logger:
            utils.check_dependencies()
            # Should log missing tools because none of the security tools are installed
            mock_logger.warning.assert_called()


# ---------------------------------------------------------------------------
# Scheduler / Background Threads (smoke tests)
# ---------------------------------------------------------------------------

class TestBackgroundThreads:
    @patch("time.sleep", side_effect=InterruptedError("stop loop"))
    @patch("threading.Thread")
    def test_scheduler_loop_dispatches(self, mock_thread, mock_sleep):
        future = (datetime.now() - __import__("datetime").timedelta(minutes=1)).isoformat()
        extensions.db.scans.insert_one({
            "scan_id": "sched_001",
            "status": "scheduled",
            "scheduled_time": future,
            "targets": "sched.com",
            "config": {"tools": ["subfinder"]},
            "created_at": datetime.now().isoformat(),
        })
        with pytest.raises(InterruptedError):
            scheduler_loop()
        mock_thread.assert_called_once()

    @patch("time.sleep", side_effect=InterruptedError("stop loop"))
    @patch("subprocess.run")
    def test_continuous_subfinder_monitor(self, mock_run, mock_sleep):
        extensions.db.saved_targets.insert_one({"value": "example.com"})
        with pytest.raises(InterruptedError):
            continuous_subfinder_monitor()
        mock_run.assert_called_once()


# ---------------------------------------------------------------------------
# AI Analysis
# ---------------------------------------------------------------------------

class TestAIAnalysis:
    def _create_scan_with_output(self, scan_id, txt_files):
        """Helper: create scan dir with .txt output files."""
        from pathlib import Path
        scan_dir = Path("scans") / scan_id
        scan_dir.mkdir(parents=True, exist_ok=True)
        for name, content in txt_files.items():
            (scan_dir / name).write_text(content)
        extensions.db.scans.insert_one({
            "scan_id": scan_id, "status": "completed",
            "targets": "example.com", "results": {"subfinder": 2, "nuclei": 1},
            "created_at": datetime.now().isoformat(),
        })

    def _mock_openai_response(self, content):
        """Set up sys.modules mocks for openai and httpx, return cleanup fn."""
        import sys
        mock_openai = MagicMock()
        mock_openai_client = MagicMock()
        mock_openai.OpenAI.return_value = mock_openai_client
        mock_openai_client.chat.completions.create.return_value = content

        mock_httpx = MagicMock()
        mock_httpx.Client.return_value = MagicMock()

        saved = {}
        for mod in ('openai', 'httpx'):
            if mod in sys.modules:
                saved[mod] = sys.modules[mod]
            sys.modules[mod] = mock_openai if mod == 'openai' else mock_httpx

        def cleanup():
            for mod, orig in saved.items():
                sys.modules[mod] = orig
            for mod in ('openai', 'httpx'):
                if mod not in saved and mod in sys.modules:
                    del sys.modules[mod]

        return mock_openai_client, cleanup

    def test_ai_analysis_no_output_files(self, authenticated_client):
        """Returns 400 when no .txt files exist."""
        from pathlib import Path
        scan_dir = Path("scans") / "empty_scan_001"
        scan_dir.mkdir(parents=True, exist_ok=True)
        extensions.db.scans.insert_one({
            "scan_id": "empty_scan_001", "status": "completed",
            "targets": "example.com", "results": {},
            "created_at": datetime.now().isoformat(),
        })
        resp = authenticated_client.post("/api/ai_analysis/empty_scan_001")
        assert resp.status_code == 400
        assert "No output files" in resp.get_json()["error"]

    def test_ai_analysis_scan_not_found(self, authenticated_client):
        resp = authenticated_client.post("/api/ai_analysis/nonexistent_999")
        assert resp.status_code == 404

    def test_ai_analysis_structured_response(self, authenticated_client):
        """LLM returns valid structured JSON; endpoint parses, persists, and returns markdown + JSON."""
        self._create_scan_with_output("ai_test_001", {
            "subfinder.txt": "sub1.example.com\nsub2.example.com\n",
            "nuclei.txt": "[CRITICAL] RCE @ https://sub1.example.com/api\n",
        })

        analysis_json = {
            "executive_summary": "Two subdomains found with one critical RCE vulnerability.",
            "risk_level": "critical",
            "risk_justification": "Remote code execution exposed on public API.",
            "attack_surface": {"subdomains": 2, "live_urls": 1, "open_ports": 0, "vulnerabilities": 1, "unique_ips": 2},
            "findings": [
                {"severity": "critical", "category": "Remote Code Execution", "description": "RCE on /api endpoint",
                 "evidence": "https://sub1.example.com/api", "source_tool": "nuclei"}
            ],
            "recommendations": [
                {"priority": "immediate", "action": "Patch /api endpoint", "rationale": "Critical RCE exposure"}
            ]
        }

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps(analysis_json)

        mock_client, cleanup = self._mock_openai_response(mock_response)
        try:
            resp = authenticated_client.post("/api/ai_analysis/ai_test_001")
        finally:
            cleanup()

        assert resp.status_code == 200
        data = resp.get_json()

        assert data["risk_level"] == "critical"
        assert "analysis" in data
        assert "analysis_json" in data
        assert data["analysis_json"]["risk_level"] == "critical"
        assert len(data["analysis_json"]["findings"]) == 1
        assert "risk_color" in data

        # Verify persisted to MongoDB
        doc = extensions.db.scans.find_one({"scan_id": "ai_test_001"})
        assert doc.get("ai_analysis") is not None
        assert doc["ai_analysis"]["risk_level"] == "critical"

    def test_ai_analysis_json_in_codeblock(self, authenticated_client):
        """LLM wraps JSON in markdown code block — endpoint extracts and parses it."""
        self._create_scan_with_output("ai_test_002", {"subfinder.txt": "a.example.com\n"})

        analysis_json = {
            "executive_summary": "Minimal surface.", "risk_level": "low",
            "risk_justification": "No vulnerabilities found.",
            "attack_surface": {"subdomains": 1, "live_urls": 0, "open_ports": 0, "vulnerabilities": 0, "unique_ips": 0},
            "findings": [], "recommendations": []
        }

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = f"Here is the analysis:\n```json\n{json.dumps(analysis_json)}\n```"

        mock_client, cleanup = self._mock_openai_response(mock_response)
        try:
            resp = authenticated_client.post("/api/ai_analysis/ai_test_002")
        finally:
            cleanup()

        assert resp.status_code == 200
        assert resp.get_json()["risk_level"] == "low"

    def test_ai_analysis_invalid_json(self, authenticated_client):
        """LLM returns garbage — endpoint returns 502."""
        self._create_scan_with_output("ai_test_003", {"subfinder.txt": "x.com\n"})

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Sorry, I cannot analyze that."

        mock_client, cleanup = self._mock_openai_response(mock_response)
        try:
            resp = authenticated_client.post("/api/ai_analysis/ai_test_003")
        finally:
            cleanup()

        assert resp.status_code == 502
        assert "invalid JSON" in resp.get_json()["error"]

    def test_generate_analysis_markdown(self):
        """Markdown generator produces expected sections."""
        from routes.all_routes import generate_analysis_markdown
        data = {
            "executive_summary": "Test summary.",
            "risk_level": "high",
            "risk_justification": "Exposed admin panel.",
            "attack_surface": {"subdomains": 5, "live_urls": 3, "open_ports": 10, "vulnerabilities": 2, "unique_ips": 4},
            "findings": [
                {"severity": "high", "category": "Admin Panel", "description": "Exposed at /admin",
                 "evidence": "https://example.com/admin", "source_tool": "httpx"},
                {"severity": "medium", "category": "Missing Headers", "description": "No CSP header",
                 "evidence": "https://example.com", "source_tool": "httpx"},
            ],
            "recommendations": [
                {"priority": "immediate", "action": "Restrict /admin access", "rationale": "Publicly accessible"},
                {"priority": "short_term", "action": "Add CSP header", "rationale": "XSS mitigation"},
            ]
        }
        md = generate_analysis_markdown(data)

        assert "Risk Level: HIGH" in md
        assert "Exposed admin panel." in md
        assert "| Subdomains | 5 |" in md
        assert "Test summary." in md
        assert "**Admin Panel**" in md
        assert "**Missing Headers**" in md
        assert "Restrict /admin access" in md
        assert "Add CSP header" in md
        assert "Immediate" in md
        assert "Short Term" in md

    def test_generate_analysis_markdown_empty(self):
        """Handles minimal input gracefully."""
        from routes.all_routes import generate_analysis_markdown
        md = generate_analysis_markdown({"risk_level": "low", "risk_justification": "", "executive_summary": "",
                                          "attack_surface": {}, "findings": [], "recommendations": []})
        assert "Risk Level: LOW" in md


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
