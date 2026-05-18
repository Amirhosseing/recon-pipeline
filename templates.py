HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Recon Pipeline</title>
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
        .ai-analysis-card { background: #fafbff; border-left: 5px solid #667eea; padding: 20px; border-radius: 8px; line-height: 1.7; white-space: pre-wrap; font-size: 14px; max-height: 60vh; overflow-y: auto; }
        .ai-analysis-card h1, .ai-analysis-card h2, .ai-analysis-card h3 { color: #333; margin-top: 15px; margin-bottom: 5px; }
        .ai-analysis-card ul, .ai-analysis-card ol { padding-left: 20px; }
        .ai-analysis-card li { margin-bottom: 3px; }
        .ai-analysis-card strong { color: #e53935; }
        .ai-analysis-card table { border-collapse: collapse; width: 100%; margin: 10px 0; }
        .ai-analysis-card th, .ai-analysis-card td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; }
        .ai-analysis-card th { background: #e8eaf6; }
        .ai-analysis-error { border-left-color: #f44336 !important; background: #fff5f5 !important; }
        .ai-analysis-loading { text-align: center; color: #667eea; font-style: italic; }
        .risk-badge { display: inline-block; padding: 6px 16px; border-radius: 20px; color: white; font-weight: 700; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; }
        .surface-stats { display: flex; gap: 15px; flex-wrap: wrap; margin: 10px 0 15px; }
        .surface-stat { background: #f5f5f5; border-radius: 8px; padding: 10px 15px; text-align: center; min-width: 80px; }
        .surface-stat .stat-num { font-size: 22px; font-weight: 700; color: #333; }
        .surface-stat .stat-label { font-size: 11px; color: #777; text-transform: uppercase; }
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
                                <div class="checkbox-item"><input type="checkbox" name="tools" value="cdncheck"><label>CDNCheck</label></div>
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
                                <div class="config-item"><label>PureDNS Args</label><input type="text" name="args_puredns" value="-q"></div>
                                <div class="config-item"><label>DNSx Args</label><input type="text" name="args_dnsx" value="-retry 3 -a -cname -ns -mx -txt -resp"></div>
                                <div class="config-item"><label>TLSx Args</label><input type="text" name="args_tlsx" value="-san -cn -serial -issuer"></div>
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
                        <div class="stage" data-stage="cdncheck"><div class="stage-header"><span class="stage-name">4. CDNCheck</span><span class="stage-status">Pending</span></div><div class="stage-output"></div><div class="progress-wrapper"><div class="progress-fill" style="width:0%"></div></div></div>
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
                <div id="aiAnalysisSection" style="margin-top: 20px; border-top: 1px solid #ddd; padding-top: 15px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <h3>AI Security Analysis <span id="riskBadge" class="risk-badge" style="display: none;"></span></h3>
                        <button class="btn" id="aiAnalysisBtn" onclick="runAIAnalysis()" style="width: auto; padding: 10px 25px;">Analyze Results</button>
                    </div>
                    <div id="surfaceStats" class="surface-stats" style="display: none;"></div>
                    <div id="aiAnalysisResult" style="display: none; margin-top: 15px;">
                        <div id="aiAnalysisContent" class="ai-analysis-card"></div>
                    </div>
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
   
    <script async src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
    <script>
        // Redirect to login on 401 from any fetch
        const _origFetch = window.fetch;
        window.fetch = function(...args) {
            return _origFetch.apply(this, args).then(res => {
                if (res.status === 401) window.location.href = '/login';
                return res;
            });
        };
        // Load Socket.IO dynamically so CDN failure doesn't block the entire page
        let socket = null;
        (function() {
            function initSocket() {
                try { socket = io(); } catch(e) { console.warn("Socket.IO not available, using polling fallback"); }
            }
            var s = document.createElement('script');
            s.src = 'https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js';
            s.onload = initSocket;
            s.onerror = function() { console.warn("Socket.IO CDN unreachable, using polling fallback"); };
            document.head.appendChild(s);
        })();
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

        // --- AI Analysis ---
        function formatAnalysis(text) {
            if (!text) return '';
            let html = text
                .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
                .replace(/^### (.+)$/gm, '<h3>$1</h3>')
                .replace(/^## (.+)$/gm, '<h2>$1</h2>')
                .replace(/^# (.+)$/gm, '<h1>$1</h1>')
                .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
                .replace(/^\* (.+)$/gm, '<li>$1</li>')
                .replace(/^- (.+)$/gm, '<li>$1</li>')
                .replace(/^\d+\. (.+)$/gm, '<li>$1</li>')
                .replace(new RegExp('\\n{2,}', 'g'), '</p><p>')
                .replace(new RegExp('\\n', 'g'), '<br>');
            return '<p>' + html + '</p>';
        }

        async function runAIAnalysis() {
            if (!currentScanId) return;
            const btn = document.getElementById('aiAnalysisBtn');
            const resultDiv = document.getElementById('aiAnalysisResult');
            const content = document.getElementById('aiAnalysisContent');
            const badge = document.getElementById('riskBadge');
            const stats = document.getElementById('surfaceStats');

            btn.disabled = true;
            btn.textContent = 'Analyzing...';
            resultDiv.style.display = 'block';
            badge.style.display = 'none';
            stats.style.display = 'none';
            content.className = 'ai-analysis-card ai-analysis-loading';
            content.textContent = 'Sending results to AI for analysis...';

            try {
                const res = await fetch(`/api/ai_analysis/${currentScanId}`, { method: 'POST' });
                const data = await res.json();
                if (!res.ok) {
                    content.className = 'ai-analysis-card ai-analysis-error';
                    content.textContent = data.error || 'Analysis failed.';
                } else {
                    // Risk badge
                    if (data.risk_level) {
                        badge.textContent = data.risk_level;
                        badge.style.display = 'inline-block';
                        badge.style.background = data.risk_color || '#666';
                    }
                    // Attack surface stats
                    const surface = data.analysis_json?.attack_surface;
                    if (surface) {
                        stats.innerHTML = Object.entries(surface).map(([k, v]) =>
                            `<div class="surface-stat"><div class="stat-num">${v}</div><div class="stat-label">${k.replace(/_/g, ' ')}</div></div>`
                        ).join('');
                        stats.style.display = 'flex';
                    }
                    content.className = 'ai-analysis-card';
                    content.innerHTML = formatAnalysis(data.analysis);
                }
            } catch (e) {
                content.className = 'ai-analysis-card ai-analysis-error';
                content.textContent = 'Error connecting to AI service.';
            }

            btn.disabled = false;
            btn.textContent = 'Analyze Results';
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
