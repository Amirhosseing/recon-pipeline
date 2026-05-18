# /analyze-scan

Analyze a completed recon scan with structured security analysis.

## Usage

```
/analyze-scan <scan_id>
```

## Instructions

You are a senior security analyst reviewing automated reconnaissance results. Your job is to produce actionable intelligence from raw scan output.

### Step 1: Locate scan data

Find the scan directory at `scans/<scan_id>/`. If the scan_id contains path separators or `..`, refuse. List available `.txt` files — these are the clean output files from each pipeline stage.

### Step 2: Read scan output

Read all `.txt` files in the scan directory. Each file corresponds to a pipeline stage:

| File | Stage | What it contains |
|------|-------|-----------------|
| `subfinder.txt` | Subfinder | Discovered subdomains |
| `dnsx.txt` | DNSx | DNS records (A, CNAME, NS, MX, TXT) |
| `nmap.txt` | Nmap | Open ports per IP |
| `tlsx.txt` | TLSx | TLS certificate info |
| `httpx.txt` | HTTPx | Live web servers with tech detection |
| `katana.txt` | Katana | Crawled endpoints |
| `vhost_all.txt` | VHost | Virtual host discoveries |
| `sni.txt` | SNI Check | SNI-based host findings |
| `nuclei.txt` | Nuclei | Vulnerability findings by severity |
| `ffuf.txt` | FFUF | Directory fuzzing results |

Also check for `active_ips.txt` (CDN-filtered IPs) and `puredns_all.txt` (brute-forced subdomains).

### Step 3: Read scan metadata

If MongoDB is accessible (check via the running app at `http://localhost:5000`), fetch scan metadata:
```bash
curl -s -b cookies.txt http://localhost:5000/scan_status/<scan_id>
```

Otherwise, infer metadata from the output files themselves (count lines, parse results).

### Step 4: Apply analysis framework

Analyze the data within these scope boundaries:

**IN SCOPE:**
- Attack surface size and exposure
- Critical/high severity vulnerabilities (RCE, SQLi, XSS, SSRF, auth bypass)
- Exposed admin panels, debug endpoints, sensitive paths
- Missing security headers, outdated software versions
- Certificate issues (expired, self-signed, weak ciphers)
- Open ports running known-vulnerable services
- Subdomain takeover candidates
- Interesting technology stack combinations

**OUT OF SCOPE:**
- Raw data listing (don't just repeat what subfinder found)
- Informational-only findings with no security impact
- Theoretical attacks without evidence in the data

### Step 5: Output structured JSON

Produce a JSON object matching this exact schema:

```json
{
  "executive_summary": "2-3 sentence overview of the attack surface and key risks",
  "risk_level": "critical|high|medium|low",
  "risk_justification": "Why this risk level was assigned",
  "attack_surface": {
    "subdomains": 0,
    "live_urls": 0,
    "open_ports": 0,
    "vulnerabilities": 0,
    "unique_ips": 0
  },
  "findings": [
    {
      "severity": "critical|high|medium|low|info",
      "category": "Short title (e.g. 'Exposed Admin Panel', 'Missing HTTPS')",
      "description": "What was found and why it matters",
      "evidence": "Specific hosts, ports, URLs, or CVEs",
      "source_tool": "Which pipeline stage found it"
    }
  ],
  "recommendations": [
    {
      "priority": "immediate|short_term|long_term",
      "action": "What to do",
      "rationale": "Why this matters"
    }
  ]
}
```

### Step 6: Render markdown

Convert the JSON to formatted markdown for display:

```markdown
# Security Analysis: <scan_id>

## Risk Level: <CRITICAL|HIGH|MEDIUM|LOW>

<risk_justification>

## Attack Surface

| Metric | Count |
|--------|-------|
| Subdomains | N |
| Live URLs | N |
| Open Ports | N |
| Vulnerabilities | N |
| Unique IPs | N |

## Executive Summary

<executive_summary>

## Findings

### Critical
- **<category>** — <description>
  - Evidence: <evidence>
  - Source: <source_tool>

### High
...

## Recommendations

### Immediate
1. **<action>** — <rationale>

### Short-term
...
```

### Output

Present both:
1. The structured JSON (in a code block for copy-paste)
2. The rendered markdown (for reading)

If the user asks to save results, write the JSON to `scans/<scan_id>/ai_analysis.json`.
