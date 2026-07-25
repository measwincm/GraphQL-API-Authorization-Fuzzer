#!/usr/bin/env python3
"""
GraphQL API Authorization Fuzzer
Detects Broken Function Level Authorization (BFLA / CWE-285)
"""

import argparse
import json
import sys
import time
import csv
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import requests

# ============================================================
# CONSTANTS
# ============================================================

INTROSPECTION_QUERY = """
query IntrospectMutations {
  __schema {
    mutationType {
      fields {
        name
        args {
          name
          type {
            kind
            name
            ofType { kind name ofType { kind name ofType { kind name } } }
          }
        }
      }
    }
  }
}
"""

SCALAR_DEFAULTS = {
    "String": '"authz-fuzzer-probe"',
    "Int": "999999999",
    "Float": "1.0",
    "Boolean": "false",
    "ID": '"999999999"',
}

# ============================================================
# HELPERS
# ============================================================

def unwrap_type(t):
    while t and t.get("name") is None and t.get("ofType"):
        t = t["ofType"]
    return t

def value_for_arg(arg):
    t = unwrap_type(arg["type"])
    name = t.get("name") or "String"
    kind = t.get("kind")
    if kind in ("SCALAR", "ENUM"):
        return SCALAR_DEFAULTS.get(name, '"authz-fuzzer-probe"')
    return "{}"

def build_mutation_query(name, args):
    if not args:
        return f"mutation {{ {name} {{ __typename }} }}"
    arg_str = ", ".join(f"{a['name']}: {value_for_arg(a)}" for a in args)
    return f"mutation {{ {name}({arg_str}) {{ __typename }} }}"

# ============================================================
# RESULT CLASS
# ============================================================

class FuzzResult:
    def __init__(self, mutation, classification, severity, detail, http_status=None):
        self.mutation = mutation
        self.classification = classification
        self.severity = severity
        self.detail = detail
        self.http_status = http_status

    def to_dict(self):
        return {
            "mutation": self.mutation,
            "classification": self.classification,
            "severity": self.severity,
            "detail": self.detail,
            "http_status": self.http_status,
        }

# ============================================================
# FUZZER CLASS
# ============================================================

class GraphQLAuthzFuzzer:
    AUTH_ERROR_HINTS = ("permission", "denied", "unauthorized", "forbidden",
                         "not authenticated", "scope", "access denied")

    def __init__(self, url, restricted_token, baseline_token=None,
                 timeout=8, retries=1, workers=4, verbose=False,
                 public_mutations=None):
        self.url = url
        self.restricted_token = restricted_token
        self.baseline_token = baseline_token
        self.timeout = timeout
        self.retries = retries
        self.workers = workers
        self.verbose = verbose
        self.public_mutations = set(public_mutations or [])
        self.session = requests.Session()
        self.results = []

    def _post(self, query, token):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        last_exc = None
        for attempt in range(self.retries + 1):
            try:
                r = self.session.post(
                    self.url, headers=headers,
                    json={"query": query}, timeout=self.timeout,
                )
                return r.status_code, r.json()
            except requests.exceptions.RequestException as e:
                last_exc = e
                time.sleep(0.3 * (attempt + 1))
        raise last_exc

    def discover_mutations(self):
        status, data = self._post(INTROSPECTION_QUERY, self.restricted_token)
        fields = (
            data.get("data", {})
            .get("__schema", {})
            .get("mutationType", {})
            .get("fields", [])
        )
        return fields if fields is not None else []

    @staticmethod
    def _looks_like_auth_error(message):
        m = message.lower()
        return any(h in m for h in GraphQLAuthzFuzzer.AUTH_ERROR_HINTS)

    def _classify_single(self, http_status, payload):
        errors = payload.get("errors")
        if http_status in (401, 403):
            return "SCOPE_BLOCKED", "Secure", "HTTP-level auth rejection before resolver"
        if errors:
            msg = errors[0].get("message", "")[:150]
            if self._looks_like_auth_error(msg):
                return "RESOLVER_DENIED", "Secure", f"Resolver enforced auth: {msg}"
            if http_status and http_status >= 400:
                return "SCHEMA_ERROR", "Info", f"Request/validation error: {msg}"
            return "RESOURCE_ERROR", "High", f"Resolver reached, non-auth error: {msg}"
        if payload.get("data") is not None:
            return "SUCCESS", "Critical", "Mutation executed successfully with restricted token"
        return "UNKNOWN", "Info", "Unrecognized response shape"

    def test_mutation(self, field):
        name = field["name"]
        query = build_mutation_query(name, field.get("args", []))

        try:
            status, payload = self._post(query, self.restricted_token)
        except Exception as e:
            return FuzzResult(name, "ERROR", "Info", str(e)[:150])

        classification, severity, detail = self._classify_single(status, payload)

        if classification == "SUCCESS" and name in self.public_mutations:
            classification, severity = "PUBLIC_BY_DESIGN", "Info"
            detail = "Marked as an intentionally public mutation (allowlisted); not a finding."

        if classification == "SUCCESS" and self.baseline_token:
            try:
                base_status, base_payload = self._post(query, self.baseline_token)
                base_class, _, _ = self._classify_single(base_status, base_payload)
                detail += f" | baseline(privileged token) result: {base_class}"
            except Exception as e:
                detail += f" | baseline check failed: {e}"

        return FuzzResult(name, classification, severity, detail, status)

    def run(self):
        fields = self.discover_mutations()
        self.results = []
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self.test_mutation, f): f for f in fields}
            for fut in as_completed(futures):
                self.results.append(fut.result())
        order = {f["name"]: i for i, f in enumerate(fields)}
        self.results.sort(key=lambda r: order.get(r.mutation, 0))
        return fields, self.results

# ============================================================
# REPORT GENERATORS
# ============================================================

def generate_html_report(url, results, path):
    """Generate HTML report with working export toggle and CSV escape"""
    critical = [r for r in results if r.severity == "Critical"]
    high = [r for r in results if r.severity == "High"]
    secure = [r for r in results if r.severity == "Secure"]

    def row(r):
        css = {"Critical": "critical", "High": "high", "Secure": "secure", "Info": "info"}.get(r.severity, "info")
        return (f"<tr><td><strong>{r.mutation}</strong></td>"
                f"<td class='{css}'>{r.classification}</td>"
                f"<td class='{css}'>{r.severity}</td>"
                f"<td>{r.detail}</td></tr>")

    def boundary_row(r):
        if r.severity == "Critical":
            arrow_class = "breach"
            tag_class = "critical"
            tag_text = "CRITICAL"
        elif r.severity == "Secure":
            arrow_class = "blocked"
            tag_class = "secure"
            tag_text = "BLOCKED — SECURE"
        elif r.classification == "PUBLIC_BY_DESIGN":
            arrow_class = "pass"
            tag_class = "info"
            tag_text = "PUBLIC BY DESIGN"
        else:
            arrow_class = "pass"
            tag_class = "info"
            tag_text = r.severity.upper()

        return f"""
      <div class="req-row">
        <div class="req-name">{r.mutation} →</div>
        <div class="req-track"><div class="arrow {arrow_class}"></div></div>
        <div class="req-result"><span class="tag {tag_class}">{tag_text}</span></div>
      </div>"""

    boundary_rows = "".join(boundary_row(r) for r in results)

    # Build results JSON for JavaScript
    results_json = json.dumps([r.to_dict() for r in results], indent=2)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>GraphQL Authz Fuzzer Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root{{
    --ink:#12151C;
    --panel:#1B212C;
    --panel-2:#202733;
    --hair:#2A313D;
    --text:#D6DCE5;
    --dim:#7C8798;
    --critical:#E5484D;
    --secure:#3DD9B3;
    --amber:#E8A33D;
    --info:#6C8CB8;
  }}
  *{{box-sizing:border-box;}}
  body{{
    margin:0;
    background:var(--ink);
    color:var(--text);
    font-family:'IBM Plex Mono', monospace;
    padding:48px 20px 80px;
  }}
  .wrap{{max-width:920px;margin:0 auto;}}

  .eyebrow{{
    font-family:'IBM Plex Sans',sans-serif;
    font-size:11px;
    letter-spacing:.18em;
    text-transform:uppercase;
    color:var(--amber);
    margin-bottom:10px;
    font-weight:600;
  }}
  h1{{
    font-family:'IBM Plex Sans',sans-serif;
    font-size:28px;
    font-weight:600;
    margin:0 0 6px;
    color:#fff;
    letter-spacing:-.01em;
  }}
  .meta{{
    color:var(--dim);
    font-size:13px;
    display:flex;
    gap:24px;
    flex-wrap:wrap;
    margin-bottom:36px;
    border-bottom:1px solid var(--hair);
    padding-bottom:20px;
  }}
  .meta span b{{color:var(--text);font-weight:500;}}

  .boundary-section{{margin:36px 0 44px;}}
  .section-label{{
    font-family:'IBM Plex Sans',sans-serif;
    font-size:11px;
    letter-spacing:.14em;
    text-transform:uppercase;
    color:var(--dim);
    margin-bottom:18px;
    font-weight:600;
  }}
  .boundary{{
    position:relative;
    background:var(--panel);
    border:1px solid var(--hair);
    border-radius:6px;
    padding:32px 40px;
    overflow:hidden;
  }}
  .boundary-line{{
    position:absolute;
    left:50%;
    top:24px;
    bottom:24px;
    width:2px;
    background:repeating-linear-gradient(180deg,var(--dim) 0 6px,transparent 6px 12px);
  }}
  .boundary-tag{{
    position:absolute;
    top:2px;
    left:50%;
    transform:translateX(-50%);
    background:var(--ink);
    color:var(--dim);
    font-size:10px;
    letter-spacing:.12em;
    padding:2px 10px;
    border:1px solid var(--hair);
    border-radius:3px;
    text-transform:uppercase;
  }}
  .lane-heads{{
    display:flex;
    justify-content:space-between;
    font-family:'IBM Plex Sans',sans-serif;
    font-size:11px;
    color:var(--dim);
    text-transform:uppercase;
    letter-spacing:.1em;
    margin-bottom:20px;
  }}
  .req-row{{
    display:flex;
    align-items:center;
    margin:14px 0;
    position:relative;
    height:22px;
  }}
  .req-name{{
    width:calc(50% - 30px);
    text-align:right;
    padding-right:14px;
    font-size:13px;
  }}
  .req-track{{
    width:60px;
    display:flex;
    align-items:center;
    justify-content:center;
    position:relative;
  }}
  .req-result{{
    width:calc(50% - 30px);
    padding-left:14px;
    font-size:12px;
  }}
  .arrow{{
    height:2px;
    position:relative;
  }}
  .arrow.blocked{{
    width:26px;
    background:var(--secure);
  }}
  .arrow.blocked::after{{
    content:'';
    position:absolute;right:-1px;top:-4px;
    width:0;height:0;
    border-top:5px solid transparent;
    border-bottom:5px solid transparent;
    border-left:6px solid var(--secure);
  }}
  .arrow.breach{{
    width:60px;
    background:var(--critical);
  }}
  .arrow.breach::after{{
    content:'';
    position:absolute;right:-1px;top:-4px;
    width:0;height:0;
    border-top:5px solid transparent;
    border-bottom:5px solid transparent;
    border-left:6px solid var(--critical);
  }}
  .arrow.pass{{
    width:60px;
    background:var(--info);
    opacity:.6;
  }}
  .arrow.pass::after{{
    content:'';
    position:absolute;right:-1px;top:-4px;
    width:0;height:0;
    border-top:5px solid transparent;
    border-bottom:5px solid transparent;
    border-left:6px solid var(--info);
    opacity:.6;
  }}
  .tag{{
    font-size:10px;
    letter-spacing:.08em;
    padding:1px 7px;
    border-radius:3px;
    font-weight:600;
    display:inline-block;
  }}
  .tag.critical{{background:rgba(229,72,77,.15);color:var(--critical);border:1px solid rgba(229,72,77,.35);}}
  .tag.secure{{background:rgba(61,217,179,.12);color:var(--secure);border:1px solid rgba(61,217,179,.3);}}
  .tag.info{{background:rgba(108,140,184,.14);color:var(--info);border:1px solid rgba(108,140,184,.3);}}

  .ledger{{
    display:grid;
    grid-template-columns:repeat(4,1fr);
    gap:1px;
    background:var(--hair);
    border:1px solid var(--hair);
    border-radius:6px;
    overflow:hidden;
    margin-bottom:40px;
  }}
  .stat{{
    background:var(--panel);
    padding:20px 18px;
  }}
  .stat .n{{font-size:30px;font-weight:600;line-height:1;}}
  .stat .l{{
    font-family:'IBM Plex Sans',sans-serif;
    font-size:11px;
    color:var(--dim);
    text-transform:uppercase;
    letter-spacing:.1em;
    margin-top:8px;
  }}
  .stat.crit .n{{color:var(--critical);}}
  .stat.sec .n{{color:var(--secure);}}
  .stat.inf .n{{color:var(--info);}}

  table{{width:100%;border-collapse:collapse;font-size:13px;}}
  th{{
    text-align:left;
    font-family:'IBM Plex Sans',sans-serif;
    font-size:11px;
    text-transform:uppercase;
    letter-spacing:.08em;
    color:var(--dim);
    padding:10px 14px;
    border-bottom:1px solid var(--hair);
    font-weight:600;
  }}
  td{{padding:12px 14px;border-bottom:1px solid var(--hair);vertical-align:top;}}
  tr:last-child td{{border-bottom:none;}}
  .mutation-name{{color:#fff;font-weight:500;}}
  .detail{{color:var(--dim);font-size:12px;}}

  .finding{{
    background:var(--panel);
    border:1px solid rgba(229,72,77,.3);
    border-left:3px solid var(--critical);
    border-radius:4px;
    padding:16px 18px;
    margin-bottom:10px;
  }}
  .finding h3{{margin:0 0 6px;font-size:14px;color:#fff;font-weight:500;}}
  .finding p{{margin:0;font-size:12px;color:var(--dim);line-height:1.5;}}

  .footer-note{{
    margin-top:40px;
    font-size:11px;
    color:var(--dim);
    border-top:1px solid var(--hair);
    padding-top:16px;
  }}

  .download-bar {{
    display: flex;
    flex-direction: column;
    gap: 10px;
    margin-bottom: 36px;
    align-items: flex-start;
  }}
  .export-toggle {{
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 10px 18px;
    border-radius: 6px;
    border: 1px solid var(--hair);
    font-size: 14px;
    font-weight: bold;
    cursor: pointer;
    color: var(--text);
    background: var(--panel);
    font-family: 'IBM Plex Mono', monospace;
    transition: border-color 0.15s ease;
  }}
  .export-toggle:hover {{
    border-color: var(--dim);
  }}
  .export-toggle .chev {{
    transition: transform 0.15s ease;
    font-size: 11px;
  }}
  .export-toggle.open .chev {{
    transform: rotate(180deg);
  }}
  .export-panel {{
    display: none;
    gap: 10px;
    flex-wrap: wrap;
    align-items: center;
    padding-left: 4px;
  }}
  .export-panel.open {{
    display: flex;
  }}
  .download-btn {{
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 10px 18px;
    border-radius: 6px;
    border: none;
    font-size: 14px;
    font-weight: bold;
    cursor: pointer;
    text-decoration: none;
    color: white;
    transition: opacity 0.15s ease;
  }}
  .download-btn:hover {{ opacity: 0.8; }}
  .download-btn.html {{ background: #3498db; }}
  .download-btn.json {{ background: #2c3e50; }}
  .download-btn.csv {{ background: #27ae60; }}
  #download-status {{
    font-size: 12px;
    color: #7f8c8d;
    margin-left: 4px;
  }}
</style>
</head>
<body>
<div class="wrap">

  <div class="eyebrow">GraphQL Authorization Fuzzer</div>
  <h1>Authorization Boundary Scan</h1>
  <div class="meta">
    <span>Target: <b>{url}</b></span>
    <span>Generated: <b>{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</b></span>
    <span>Mutations tested: <b>{len(results)}</b></span>
  </div>

  <div class="download-bar">
    <button class="export-toggle" id="export-toggle" onclick="toggleExportPanel()">
      ⬇ Export <span class="chev" id="chev">▾</span>
    </button>
    <div class="export-panel" id="export-panel">
      <button class="download-btn html" onclick="downloadHtmlReport()">⬇ HTML Report</button>
      <button class="download-btn json" onclick="downloadJsonReport()">⬇ JSON Report</button>
      <button class="download-btn csv" onclick="downloadCsvReport()">⬇ CSV Report</button>
      <span id="download-status"></span>
    </div>
  </div>

  <div class="ledger">
    <div class="stat crit"><div class="n">{len(critical)}</div><div class="l">Critical</div></div>
    <div class="stat"><div class="n" style="color:var(--dim)">{len(high)}</div><div class="l">High</div></div>
    <div class="stat sec"><div class="n">{len(secure)}</div><div class="l">Secure</div></div>
    <div class="stat inf"><div class="n">{len(results) - len(critical) - len(high) - len(secure)}</div><div class="l">Info</div></div>
  </div>

  <div class="boundary-section">
    <div class="section-label">Where each request landed</div>
    <div class="boundary">
      <div class="boundary-tag">Authorization Boundary</div>
      <div class="boundary-line"></div>
      <div class="lane-heads">
        <span>Restricted Token Sends</span>
        <span>Resolver Response</span>
      </div>
      {boundary_rows}
    </div>
  </div>

  <div class="boundary-section">
    <div class="section-label">Detailed Results</div>
    <table>
      <tr><th>Mutation</th><th>Classification</th><th>Severity</th><th>Detail</th></tr>
      {''.join(row(r) for r in results)}
    </table>
  </div>

  <div class="boundary-section">
    <div class="section-label">Critical Findings</div>
    {''.join(f'<div class="finding"><h3>{r.mutation} — Broken Function Level Authorization</h3><p>{r.detail}</p></div>' for r in critical) if critical else '<p>✅ No critical vulnerabilities found.</p>'}
  </div>

  <div class="footer-note">
    CWE-285 — Improper Authorization · Generated by GraphQL Authorization Fuzzer
  </div>

</div>

<script>
// ============================================================
// CSV ESCAPE FUNCTION
// ============================================================
function csvEscape(field) {{
  var s = (field === null || field === undefined) ? '' : String(field);
  return '"' + s.replace(/"/g, '""') + '"';
}}

function toggleExportPanel() {{
  var panel = document.getElementById('export-panel');
  var toggle = document.getElementById('export-toggle');
  var chev = document.getElementById('chev');
  panel.classList.toggle('open');
  toggle.classList.toggle('open');
  if (panel.classList.contains('open')) {{
    chev.textContent = '▴';
  }} else {{
    chev.textContent = '▾';
  }}
}}

function downloadHtmlReport() {{
  var status = document.getElementById('download-status');
  status.textContent = '⏳ Generating HTML...';

  var htmlContent = '<!DOCTYPE html>\\n' + document.documentElement.outerHTML;
  var blob = new Blob([htmlContent], {{ type: 'text/html' }});
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = 'graphql_authz_report.html';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  status.textContent = '✅ HTML Downloaded!';
  setTimeout(function() {{ status.textContent = ''; }}, 3000);
}}

function downloadJsonReport() {{
  var status = document.getElementById('download-status');
  status.textContent = '⏳ Generating JSON...';

  var data = {results_json};
  var blob = new Blob([JSON.stringify({{'target': '{url}', 'generated': '{datetime.now(timezone.utc).isoformat()}', 'results': data}}, null, 2)], {{ type: 'application/json' }});
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = 'report.json';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  status.textContent = '✅ JSON Downloaded!';
  setTimeout(function() {{ status.textContent = ''; }}, 3000);
}}

function downloadCsvReport() {{
  var status = document.getElementById('download-status');
  status.textContent = '⏳ Generating CSV...';

  var data = {results_json};
  var header = ['Mutation', 'Classification', 'Severity', 'Detail', 'HTTP Status'];
  var lines = [header.map(csvEscape).join(',')];
  data.forEach(function(r) {{
    lines.push([r.mutation, r.classification, r.severity, r.detail, r.http_status].map(csvEscape).join(','));
  }});
  var blob = new Blob([lines.join('\\r\\n')], {{ type: 'text/csv' }});
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = 'report.csv';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  status.textContent = '✅ CSV Downloaded!';
  setTimeout(function() {{ status.textContent = ''; }}, 3000);
}}
</script>
</body></html>"""
    
    with open(path, "w") as f:
        f.write(html)
    print(f"✅ HTML report: {path}")

def generate_json_report(results, path):
    data = {
        "target": "http://localhost:5013/graphql",
        "generated": datetime.now(timezone.utc).isoformat(),
        "results": [r.to_dict() for r in results],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"✅ JSON report: {path}")

def generate_csv_report(results, path):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Mutation", "Classification", "Severity", "Detail", "HTTP Status"])
        for r in results:
            writer.writerow([r.mutation, r.classification, r.severity, r.detail, r.http_status])
    print(f"✅ CSV report: {path}")

# ============================================================
# MAIN
# ============================================================

def main():
    ap = argparse.ArgumentParser(description="GraphQL API Authorization Fuzzer")
    ap.add_argument("--url", required=True, help="GraphQL endpoint")
    ap.add_argument("--token", required=True, help="Restricted token")
    ap.add_argument("--baseline-token", help="Privileged token")
    ap.add_argument("--public-mutations", default="", help="Comma-separated public mutations")
    ap.add_argument("--timeout", type=float, default=8, help="Request timeout")
    ap.add_argument("--retries", type=int, default=1, help="Retry count")
    ap.add_argument("--workers", type=int, default=4, help="Concurrent threads")
    ap.add_argument("--html-out", default="report.html", help="HTML output")
    ap.add_argument("--json-out", default="report.json", help="JSON output")
    ap.add_argument("--csv-out", default="report.csv", help="CSV output")
    args = ap.parse_args()

    fuzzer = GraphQLAuthzFuzzer(
        url=args.url,
        restricted_token=args.token,
        baseline_token=args.baseline_token,
        timeout=args.timeout,
        retries=args.retries,
        workers=args.workers,
        public_mutations=[m.strip() for m in args.public_mutations.split(",") if m.strip()],
    )

    print("=" * 60)
    print("🔍 GRAPHQL AUTHORIZATION FUZZER")
    print("=" * 60)
    print(f"🌐 Target: {args.url}")
    print(f"🔑 Token: {args.token[:20]}...")
    print("=" * 60)

    print("\n🔎 Discovering mutations...")
    fields, results = fuzzer.run()

    if not fields:
        print("❌ No mutations found.")
        sys.exit(1)

    print(f"✅ Found {len(fields)} mutation(s)")

    print("\n🧪 Results:")
    for r in results:
        icon = {"Critical": "🔴", "High": "🟠", "Secure": "✅", "Info": "ℹ️"}.get(r.severity, "ℹ️")
        print(f"  → {r.mutation:<20} {icon} {r.classification} ({r.severity})")

    critical = [r for r in results if r.severity == "Critical"]
    print("\n" + "=" * 60)
    print("📊 SUMMARY")
    print("=" * 60)
    print(f"Total: {len(results)} | 🔴 Critical: {len(critical)}")

    if critical:
        print("\n⚠️ CRITICAL VULNERABILITIES:")
        for r in critical:
            print(f"   → {r.mutation}: {r.detail}")

    generate_html_report(args.url, results, args.html_out)
    generate_json_report(results, args.json_out)
    generate_csv_report(results, args.csv_out)

    print(f"\n📄 Reports: {args.html_out}, {args.json_out}, {args.csv_out}")

if __name__ == "__main__":
    main()
