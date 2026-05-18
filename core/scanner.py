import os
import json
import logging
import subprocess
import shlex
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

from extensions import socketio, db, scan_queue
from config import logger
from utils import get_tool_path, parse_json_lines_helper, count_file_lines, generate_unique_scan_id
import telegram


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
        telegram.send_telegram_alert(f"🛑 Scan Stopped by User\nTarget: {self.targets[:50]}...")

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
            telegram.send_telegram_document(str(clean_file), caption=caption)
            return

        if os.path.getsize(file_path) > 10 * 1024 * 1024:
            telegram.send_telegram_document(str(file_path), caption=caption + " (Large Raw File)")
            return
            
        if tool == 'nuclei' and file_path.suffix in ['.json', '.jsonl']:
            logger.info(f"Skipping raw nuclei JSON telegram send for {file_path}")
            return

        telegram.send_telegram_document(str(file_path), caption=caption)

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
                                parts = [entry.get('host', '')]
                                for rec in ['a', 'cname', 'ns', 'mx', 'txt']:
                                    vals = entry.get(rec, [])
                                    if vals:
                                        parts.append(f"{rec.upper()}={', '.join(str(v) for v in vals)}")
                                out_line = ' | '.join(parts) if len(parts) > 1 else parts[0]
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
                telegram.send_telegram_alert(f"🆕 **Initial Scan Completed for:** `{self.targets[:50]}`\nFound **{len(found_subdomains)}** subdomains.")
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
                telegram.send_telegram_alert(msg)
        except Exception as e: 
            logger.error(f"Failed to compare and notify subdomains: {e}")

    def run(self):
        try:
            db.scans.update_one({'scan_id': self.scan_id}, {'$set': {'status': 'running'}})
        except Exception as e:
            logger.error(f"Failed to set status to running for {self.scan_id}: {e}")
            return

        start_time = datetime.now()
        telegram.send_telegram_alert(f"🚀 Scan Started (Resumed: {self.resume_mode})\nTarget: {self.targets[:50]}")
        
        # IMPORTANT: target_list contains ONLY the original user-provided target domains
        # PureDNS bruteforce should ONLY run on these original target domains, NOT on discovered subdomains
        target_list = [t.strip() for t in self.targets.split('\n') if t.strip()]
        
        # current_targets will accumulate all discovered subdomains from subfinder, puredns, etc.
        # This is used for downstream tools like dnsx, httpx, etc.
        current_targets = target_list.copy()
        live_urls = [] 
        nmap_targets = []
        
        def get_args(tool_key: str, default: str = "") -> List[str]:
            val = self.tool_args.get(tool_key, default)
            return shlex.split(val) if val else shlex.split(default)
        
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
                        # Write targets to a file for subfinder's -dL flag
                        targets_file = self.output_dir / 'subfinder_targets.txt'
                        with open(targets_file, 'w') as f:
                            f.write('\n'.join(target_list))
                        base_args = get_args('args_subfinder', '-rl 1 -all')
                        cmd = ['subfinder'] + base_args + ['-silent', '-json', '-o', str(outfile), '-dL', str(targets_file)]
                        cmd = add_proxy('subfinder', cmd)
                        # Subfinder runs on original target domains (target_list)
                        _, err = self.run_command(cmd)
                        if not self.stopped:
                            if err or not outfile.exists():
                                self.update_stage('subfinder', 'error', f"Subfinder failed: {_}", progress=0)
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
                                for key in ('a', 'ans'):
                                    vals = res.get(key, [])
                                    if isinstance(vals, list):
                                        all_ips.update(v for v in vals if v and not v.startswith('('))
                            self.safe_ips = all_ips
                    else:
                        if self.stopped: return
                        self.update_stage('dnsx', 'running', 'Resolving DNS records...', progress=0)
                        outfile = self.output_dir / 'dnsx.json'
                        # DNSx resolves all discovered subdomains (current_targets)
                        base_args = get_args('args_dnsx', '-retry 3 -a -cname -ns -mx -txt -resp')
                        cmd = ['dnsx'] + base_args + ['-silent', '-json', '-o', str(outfile)]
                        cmd = add_proxy('dnsx', cmd)
                        _, err = self.run_command(cmd, input_data='\n'.join(current_targets))
                        if not self.stopped:
                            if err or not outfile.exists():
                                self.update_stage('dnsx', 'error', f"DNSx failed to run: {_}", progress=0)
                            else:
                                self.generate_clean_output('dnsx', outfile)
                                self.format_and_send_telegram('dnsx', outfile, caption=f"📄 DNSx Results")
                                results = parse_json_lines_helper(outfile)
                                all_ips = set()
                                for res in results:
                                    for key in ('a', 'ans'):
                                        vals = res.get(key, [])
                                        if isinstance(vals, list):
                                            all_ips.update(v for v in vals if v and not v.startswith('('))
                                self.safe_ips = all_ips
                                self.update_results('dnsx', len(results))
                                self.update_stage('dnsx', 'completed', f"Resolved {len(results)} records", progress=100)
                except Exception as e:
                    logger.error(f"Stage 3 DNSx failed: {e}")
                    self.update_stage('dnsx', 'error', str(e), progress=0)

            # 4. Cut-CDN
            if 'cdncheck' in self.selected_tools:
                try:
                    if self.resume_mode and self.status.get('stages', {}).get('cdncheck', {}).get('status') == 'completed':
                        logger.info("Skipping Cut-CDN (Completed)")
                        active_ips_file = self.output_dir / 'active_ips.txt'
                        if active_ips_file.exists():
                            self.safe_ips = set(active_ips_file.read_text().splitlines())
                            removed_count = self.status.get('results', {}).get('cdncheck', 0)
                            self.update_results('cdncheck', removed_count)
                    else:
                        if self.safe_ips:
                            if self.stopped: return
                            self.update_stage('cdncheck', 'running', 'Filtering CDN IPs...', progress=0)
                            initial_count = len(self.safe_ips)
                            out, err = self.run_command(['cdncheck', '-silent', '-nc', '-e'], input_data='\n'.join(self.safe_ips))
                            if not self.stopped:
                                if err or not out:
                                    self.update_stage('cdncheck', 'error', f"CDNCheck failed: {out}", progress=0)
                                else:
                                    # cdncheck outputs non-CDN IPs to stdout
                                    filtered = set(l.strip() for l in out.split('\n') if l.strip() and not l.startswith('['))
                                    active_ips_file = self.output_dir / 'active_ips.txt'
                                    if filtered:
                                        self.safe_ips = filtered
                                        with open(active_ips_file, 'w') as f:
                                            f.write('\n'.join(self.safe_ips))
                                    removed_count = initial_count - len(self.safe_ips)
                                    self.update_results('cdncheck', removed_count)
                                    self.format_and_send_telegram('cdncheck', active_ips_file, caption=f"📄 CDNCheck Results (Active IPs)")
                                    self.update_stage('cdncheck', 'completed', f"Filtered {removed_count} CDN IPs", progress=100)
                        else:
                            self.update_stage('cdncheck', 'skipped', "No IPs to filter", progress=100)
                except Exception as e:
                    logger.error(f"Stage 4 Cut-CDN failed: {e}")
                    self.update_stage('cdncheck', 'error', str(e), progress=0)
            
            # 5. Nmap (Moved Up)
            if 'nmap' in self.selected_tools:
                try:
                    if self.resume_mode and self.status.get('stages', {}).get('nmap', {}).get('status') == 'completed':
                        logger.info("Skipping Nmap (Completed)")
                    else:
                        targets_scan = list(self.safe_ips) if 'cdncheck' in self.selected_tools and self.safe_ips else []
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
                telegram.send_telegram_alert(f"✅ Scan Finished\nTarget: {self.targets[:50]}\nDuration: {str(duration).split('.')[0]}")
            
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
