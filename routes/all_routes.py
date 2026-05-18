import os
import pathlib
import io
import csv
import json
import zipfile
import shutil
import threading

from datetime import datetime

from flask import request, jsonify, send_file, session, redirect, url_for, abort, render_template_string
from flask_socketio import join_room
from werkzeug.utils import secure_filename
from pymongo.errors import DuplicateKeyError

from extensions import app, socketio, db, scan_queue
from config import logger, ADMIN_USERNAME, ADMIN_PASSWORD, REQUIRED_TOOLS, LLM_API_KEY, LLM_BASE_URL, LLM_MODEL, ANALYSIS_SCHEMA
from utils import parse_json_lines_helper, generate_unique_scan_id
from templates import HTML_TEMPLATE, LOGIN_TEMPLATE
from core.scanner import ScanRunner


def login_required(f):
    import functools
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
                return jsonify({'error': 'Authentication required'}), 401
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


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
        excluded = {'requirements.txt', 'docker-compose.yml', 'dockerfile', 'readme.txt'}
        files = [
            f for f in os.listdir('.')
            if os.path.isfile(f) and f.endswith('.txt') and f.lower() not in excluded
        ]
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
    
    tool_args = {f'args_{k}': str(request.form.get(f'args_{k}', '')) for k in ['subfinder', 'dnsx', 'puredns', 'httpx', 'katana', 'nmap', 'tlsx', 'vhost', 'ffuf', 'nuclei', 'gowitness']}
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
    scan_dir = pathlib.Path(f'scans/{safe_scan_id}')
    
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
    scan_dir = pathlib.Path(f'scans/{safe_scan_id}')
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
        scan_dir = pathlib.Path(f'scans/{safe_scan_id}').resolve()
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
    scan_dir = pathlib.Path(f'scans/{safe_scan_id}')
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


# --- AI Analysis Route ---

RISK_COLORS = {'critical': '#d32f2f', 'high': '#f57c00', 'medium': '#fbc02d', 'low': '#388e3c', 'info': '#1976d2'}

def generate_analysis_markdown(data):
    """Convert structured analysis JSON to formatted markdown for UI display."""
    risk = data.get('risk_level', 'unknown').upper()
    lines = [f"## Risk Level: {risk}\n"]
    lines.append(data.get('risk_justification', '') + '\n')

    surface = data.get('attack_surface', {})
    if surface:
        lines.append('## Attack Surface\n')
        lines.append('| Metric | Count |')
        lines.append('|--------|-------|')
        for key, val in surface.items():
            lines.append(f'| {key.replace("_", " ").title()} | {val} |')
        lines.append('')

    summary = data.get('executive_summary', '')
    if summary:
        lines.append(f'## Executive Summary\n\n{summary}\n')

    findings = data.get('findings', [])
    if findings:
        lines.append('## Findings\n')
        by_sev = {}
        for f in findings:
            sev = f.get('severity', 'info')
            by_sev.setdefault(sev, []).append(f)
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            items = by_sev.get(sev, [])
            if not items:
                continue
            lines.append(f'### {sev.upper()}')
            for item in items:
                lines.append(f'- **{item.get("category", "")}** — {item.get("description", "")}')
                if item.get('evidence'):
                    lines.append(f'  - Evidence: {item["evidence"]}')
                if item.get('source_tool'):
                    lines.append(f'  - Source: {item["source_tool"]}')
            lines.append('')

    recs = data.get('recommendations', [])
    if recs:
        lines.append('## Recommendations\n')
        by_pri = {}
        for r in recs:
            pri = r.get('priority', 'long_term')
            by_pri.setdefault(pri, []).append(r)
        for pri in ['immediate', 'short_term', 'long_term']:
            items = by_pri.get(pri, [])
            if not items:
                continue
            lines.append(f'### {pri.replace("_", " ").title()}')
            for i, item in enumerate(items, 1):
                lines.append(f'{i}. **{item.get("action", "")}** — {item.get("rationale", "")}')
            lines.append('')

    return '\n'.join(lines)


@app.route('/api/ai_analysis/<scan_id>', methods=['POST'])
@login_required
def ai_analysis(scan_id):
    safe_scan_id = secure_filename(scan_id)
    scan_dir = pathlib.Path(f'scans/{safe_scan_id}')

    if not scan_dir.exists():
        return jsonify({'error': 'Scan not found'}), 404

    # Gather all clean output .txt files
    max_bytes = 100 * 1024  # 100KB cap
    scan_outputs = []
    total_size = 0

    for f in sorted(scan_dir.glob('*.txt')):
        if total_size >= max_bytes:
            break
        try:
            content = f.read_text(encoding='utf-8', errors='ignore').strip()
            if not content:
                continue
            remaining = max_bytes - total_size
            if len(content) > remaining:
                content = content[:remaining] + '\n... (truncated)'
            scan_outputs.append(f"=== {f.name} ===\n{content}")
            total_size += len(content)
        except Exception:
            continue

    if not scan_outputs:
        return jsonify({'error': 'No output files found for analysis'}), 400

    # Get scan metadata
    doc = db.scans.find_one({'scan_id': safe_scan_id}, {'_id': 0, 'targets': 1, 'results': 1})
    targets = doc.get('targets', 'unknown') if doc else 'unknown'
    results = doc.get('results', {}) if doc else {}
    results_summary = ', '.join(f"{k}: {v}" for k, v in results.items()) if results else 'no counts'

    schema_str = json.dumps(ANALYSIS_SCHEMA['properties'], indent=2)

    system_prompt = """You are a senior security analyst. Analyze automated reconnaissance scan results and produce actionable intelligence.

SCOPE — Focus on:
- Attack surface size and exposure
- Critical/high severity vulnerabilities (RCE, SQLi, XSS, SSRF, auth bypass)
- Exposed admin panels, debug endpoints, sensitive paths
- Missing security headers, outdated software
- Certificate issues (expired, self-signed, weak ciphers)
- Open ports running known-vulnerable services
- Subdomain takeover candidates

OUT OF SCOPE — Do not include:
- Raw data listings (don't repeat what each tool found line by line)
- Informational findings with no security impact
- Theoretical attacks without evidence

You MUST respond with valid JSON matching this schema:
""" + schema_str

    user_prompt = f"""Analyze this reconnaissance scan.

Target: {targets}
Results Summary: {results_summary}

Scan Output:
{chr(10).join(scan_outputs)}

Respond with a JSON object matching the schema. Do not include markdown or text outside the JSON."""

    try:
        import httpx
        from openai import OpenAI
        # Bypass SOCKS proxy for LLM calls — proxy env vars interfere with httpx
        # even when proxy=None is set, so we temporarily remove them
        _proxy_keys = ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy']
        _saved_proxies = {k: os.environ.pop(k) for k in _proxy_keys if k in os.environ}
        try:
            http_client = httpx.Client(timeout=60.0)
            client = OpenAI(base_url=LLM_BASE_URL, api_key=LLM_API_KEY or "dummy", http_client=http_client, timeout=60.0)
            response = client.chat.completions.create(
                model=LLM_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                max_tokens=4000,
                temperature=0.2,
                response_format={"type": "json_object"},
            )
            raw = response.choices[0].message.content
        finally:
            os.environ.update(_saved_proxies)

        # Parse structured JSON response
        try:
            analysis_data = json.loads(raw)
        except json.JSONDecodeError:
            # Fallback: try to extract JSON from markdown code block
            import re
            match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', raw, re.DOTALL)
            if match:
                analysis_data = json.loads(match.group(1))
            else:
                return jsonify({'error': 'LLM returned invalid JSON', 'raw': raw}), 502

        # Persist to MongoDB
        db.scans.update_one(
            {'scan_id': safe_scan_id},
            {'$set': {'ai_analysis': analysis_data, 'ai_analysis_at': datetime.now().isoformat()}}
        )

        # Generate markdown for UI display
        markdown = generate_analysis_markdown(analysis_data)

        return jsonify({
            'analysis': markdown,
            'analysis_json': analysis_data,
            'risk_level': analysis_data.get('risk_level', 'unknown'),
            'risk_color': RISK_COLORS.get(analysis_data.get('risk_level', ''), '#666')
        })
    except Exception as e:
        logger.error(f"AI analysis failed for {safe_scan_id}: {e}")
        return jsonify({'error': f'AI analysis failed: {str(e)}'}), 502

