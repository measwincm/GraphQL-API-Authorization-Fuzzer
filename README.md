
# 🔍 GraphQL API Authorization Fuzzer

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Testing-red.svg)](https://owasp.org/www-project-api-security/)
[![GraphQL](https://img.shields.io/badge/GraphQL-API-purple.svg)](https://graphql.org/)

Automated GraphQL API security testing tool that detects **Broken Function Level Authorization (BFLA)** vulnerabilities by testing restricted tokens against mutations.

## 📖 Table of Contents

- [Overview](#overview)
- [Why This Project](#why-this-project)
- [Features](#features)
- [Dashboard Preview](#dashboard-preview)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Dashboard Guide](#dashboard-guide)
- [Command Line Options](#command-line-options)
- [Sample Output](#sample-output)
- [Reports](#reports)
- [Project Structure](#project-structure)
- [Technologies Used](#technologies-used)
- [Limitations](#limitations)
- [Future Improvements](#future-improvements)
- [License](#license)
- [Author](#author)

---

## 📌 Overview

The **GraphQL API Authorization Fuzzer** is an automated security testing tool that detects **Broken Function Level Authorization (BFLA)** vulnerabilities in GraphQL APIs. It tests whether a restricted (low-privilege) token can execute mutations it shouldn't have access to.

### Core Workflow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         COMPLETE WORKFLOW                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐                                                        │
│  │    DISCOVERY    │  ← GraphQL Introspection                               │
│  │   Mutations     │  ← Automatically finds all mutations                   │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────┐                                                        │
│  │     ATTACK      │  ← Low-privilege token                                 │
│  │   Simulation    │  ← Executes every mutation                             │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────┐                                                        │
│  │  CLASSIFICATION │  ← CRITICAL / SECURE / HIGH / INFO                     │
│  │                 │  ← Authorization boundary check                        │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────┐                                                        │
│  │    REPORTING    │  ← HTML / JSON / CSV                                   │
│  │                 │  ← Authorization boundary diagram                      │
│  └─────────────────┘                                                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Why This Project

### The Problem
Most APIs check authentication (is the user logged in?) carefully, but often fail to check authorization (is this specific user allowed to run this specific action?). This gap is a well-known vulnerability class called **Broken Function Level Authorization (BFLA)**, catalogued as **CWE-285**.

### Real-World Impact
- **CVE-2025-11340**: GitLab's read-only tokens could execute write mutations
- **OWASP API Security Top 10**: #5 - Broken Function Level Authorization
- **Companies using GraphQL**: GitHub, Shopify, Netflix, Meta
- **GraphQL adoption**: Growing 30% year-over-year

### Why This Tool Matters
- ✅ Automates manual security testing
- ✅ Reduces human error
- ✅ Generates audit-ready reports
- ✅ Can be integrated into CI/CD pipelines
- ✅ **NEW**: Real-time dashboard for live monitoring

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Schema Discovery** | Automatically discovers all mutations via GraphQL introspection |
| 🧪 **Intelligent Input** | Creates valid test inputs based on argument types |
| 📊 **Response Classification** | Categorizes results into CRITICAL, HIGH, SECURE, and INFO |
| 📄 **Multiple Reports** | HTML (interactive dashboard), JSON (CI/CD), CSV (Excel) |
| 🎨 **Professional HTML Report** | Interactive report with authorization boundary diagrams |
| 📊 **Live Dashboard** | **NEW!** Real-time monitoring with WebSocket updates |
| 📈 **Severity Charts** | Visual representation of vulnerability distribution |
| ⚡ **Real-time Progress** | Live progress bar and mutation status updates |
| 💾 **Export Results** | One-click export of scan results to JSON |
| 🔄 **Concurrent Testing** | Multi-threaded for fast execution |
| ⚙️ **CLI Interface** | Full command-line configuration |
| 🛡️ **False-Positive Reduction** | Public mutation allowlist and baseline token verification |
| 📦 **Lightweight** | Minimal dependencies |

---

## 🖥️ Dashboard Preview

### Live Dashboard Interface

```
GRAPHQL AUTHZ FUZZER                                      ● READY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

┌─ SCAN CONFIGURATION ─────────────┐    ┌─ SEVERITY ──────────────────────────┐
│                                  │    │                                     │
│  GraphQL Endpoint                │    │  CRITICAL    ████████████   5       │
│  ************************        │    │  HIGH        ██             1       │
│                                  │    │  SECURE      ░░             0       │
│  Restricted Token                │    │  INFO        ██             1       │
│  ************************        │    │                                     │
│                                  │    └─────────────────────────────────────┘
│  Public Mutations                │
│  ________________________        │    ┌─ SCAN PROGRESS ─────────────────────┐
│                                  │    │                                     │
│  [ START SCAN ]                  │    │  ██████████████████████████  100%   │
│                                  │    │                                     │
└──────────────────────────────────┘    └─────────────────────────────────────┘


┌─ PROGRESS ───────────────────────┐    ┌─ RESULTS ───────────────────────────┐
│                                  │    │                                     │
│  Testing: importPaste            │    │  Mutation       Status    Severity  │
│                                  │    │  ─────────────────────────────────  │
│  ████████████████████████ 100%   │    │  createPaste    SUCCESS   Critical  │
│                                  │    │  editPaste      SUCCESS   Critical  │
│  7 / 7  Completed!               │    │  deletePaste    SUCCESS   Critical  │
│                                  │    │  uploadPaste    SUCCESS   Critical  │
└──────────────────────────────────┘    │  importPaste    SUCCESS   Critical  │
                                        │                                     │
┌─ QUICK STATS ────────────────────┐    └─────────────────────────────────────┘
│                                  │
│  5 Critical   1 High             │
│  0 Secure     7 Total            │
└──────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

```bash
# Python 3.9+
python3 --version

# Docker (for DVGA target)
docker --version
```

### Step 1: Clone the Repository

```bash
git clone https://github.com/measwincm/GraphQL-API-Authorization-Fuzzer.git
cd GraphQL-API-Authorization-Fuzzer
```

### Step 2: Install Dependencies

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install requirements
pip install -r requirements.txt
```

### Step 3: Start DVGA Container (Testing Target)

```bash
docker run -d -t -p 5013:5013 -e WEB_HOST=0.0.0.0 --name dvga dolevf/dvga
```

### Step 4: Get Authentication Token

```bash
# Create user
curl -X POST http://localhost:5013/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { createUser(userData: {username: \"vaptuser\", password: \"vaptpass123\", email: \"vapt@test.com\"}) { user { username } } }"}'

# Get token
TOKEN=$(curl -s -X POST http://localhost:5013/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { login(username: \"vaptuser\", password: \"vaptpass123\") { accessToken } }"}' \
  | python3 -c "import sys, json; data=json.load(sys.stdin); print(data['data']['login']['accessToken'])")

echo "$TOKEN" > htoken.txt
```

### Step 5: Run the Dashboard

```bash
# Start the dashboard
python3 dashboard/server.py

# Open browser to http://127.0.0.1:5000
```

### Step 6: Run the CLI Fuzzer

```bash
python3 graphql_authz_fuzzer.py \
  --url http://localhost:5013/graphql \
  --token "$(cat htoken.txt)" \
  --public-mutations "login,createUser" \
  --html-out report.html \
  --json-out report.json \
  --csv-out report.csv
```

---

## 📦 Installation

### Clone the Repository

```bash
git clone https://github.com/measwincm/GraphQL-API-Authorization-Fuzzer.git
cd GraphQL-API-Authorization-Fuzzer
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Make Script Executable

```bash
chmod +x graphql_authz_fuzzer.py
```

---

## 🛠️ Usage

### Command Line Interface (CLI)

```bash
python3 graphql_authz_fuzzer.py \
  --url <GRAPHQL_ENDPOINT> \
  --token <RESTRICTED_TOKEN> \
  --public-mutations "login,createUser"
```

### With Baseline Token (Recommended)

```bash
python3 graphql_authz_fuzzer.py \
  --url http://localhost:5013/graphql \
  --token "$(cat htoken.txt)" \
  --baseline-token <PRIVILEGED_TOKEN> \
  --public-mutations "login,createUser" \
  --html-out report.html \
  --json-out report.json \
  --csv-out report.csv
```

### Interactive Mode

```bash
python3 cli/enhanced_cli.py --interactive
```

### Dashboard Mode

```bash
# Start the dashboard server
python3 dashboard/server.py

# Open browser to http://127.0.0.1:5000
```

---

## 🖥️ Dashboard Guide

### Dashboard Features

1. **Configuration Panel**
   - GraphQL Endpoint URL
   - Restricted Token (required)
   - Baseline Token (optional)
   - Public Mutations (comma-separated)
   - Worker count
   - Timeout in seconds

2. **Real-time Progress**
   - Live progress bar
   - Current mutation being tested
   - Completion percentage
   - Mutations tested / Total

3. **Quick Stats**
   - Critical vulnerabilities count
   - High severity count
   - Secure mutations count
   - Total mutations tested

4. **Visualizations**
   - Severity distribution (donut chart)
   - Scan progress (bar chart)

5. **Results Table**
   - Mutation name
   - Classification (SUCCESS, ERROR, etc.)
   - Severity (Critical, High, Secure, Info)
   - Detailed error/success messages

6. **Export Functionality**
   - One-click export to JSON
   - Download scan results

---

## ⚙️ Command Line Options

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--url` | ✅ Yes | - | GraphQL endpoint URL |
| `--token` | ✅ Yes | - | Restricted/low-privilege token |
| `--baseline-token` | ❌ No | - | Privileged token for cross-check |
| `--public-mutations` | ❌ No | "" | Comma-separated public mutations |
| `--timeout` | ❌ No | 8 | Request timeout in seconds |
| `--retries` | ❌ No | 1 | Retry count on connection errors |
| `--workers` | ❌ No | 4 | Concurrent request threads |
| `--html-out` | ❌ No | `report.html` | HTML output path |
| `--json-out` | ❌ No | `report.json` | JSON output path |
| `--csv-out` | ❌ No | `report.csv` | CSV output path |
| `--verbose` | ❌ No | False | Verbose output |

---

## 📊 Sample Output

```
============================================================
🔍 GRAPHQL AUTHORIZATION FUZZER
============================================================
🌐 Target: http://localhost:5013/graphql
🔑 Token: eyJ0eXAiOiJKV1QiLCJ...
============================================================

🔎 Discovering mutations...
✅ Found 7 mutation(s)

🧪 Results:
  → createPaste          🔴 SUCCESS (Critical)
  → editPaste            🔴 SUCCESS (Critical)
  → deletePaste          🔴 SUCCESS (Critical)
  → uploadPaste          🔴 SUCCESS (Critical)
  → importPaste          🔴 SUCCESS (Critical)
  → createUser           ℹ️ SCHEMA_ERROR (Info)
  → login                🟠 RESOURCE_ERROR (High)

============================================================
📊 SUMMARY
============================================================
Total: 7 | 🔴 Critical: 5

⚠️ CRITICAL VULNERABILITIES:
   → createPaste: Mutation executed successfully with restricted token
   → editPaste: Mutation executed successfully with restricted token
   → deletePaste: Mutation executed successfully with restricted token
   → uploadPaste: Mutation executed successfully with restricted token
   → importPaste: Mutation executed successfully with restricted token
✅ HTML report: report.html
✅ JSON report: report.json
✅ CSV report: report.csv
```

---

## 📁 Reports

### HTML Report (`report.html`)
- Dark-themed professional design
- Authorization boundary diagram
- Color-coded severity levels
- Interactive download buttons (HTML, JSON, CSV)

### JSON Report (`report.json`)
- Machine-readable format
- Ideal for CI/CD pipelines
- Contains all findings with details

### CSV Report (`report.csv`)
- Excel-compatible
- Easy to analyze and share
- Perfect for tracking over time

---

## 📂 Project Structure

```
GraphQL-API-Authorization-Fuzzer/
├── graphql_authz_fuzzer.py    # Main fuzzer script
├── dashboard/                  # Web dashboard
│   ├── server.py              # Flask server
│   └── templates/
│       └── dashboard.html     # Dashboard UI
├── cli/                       # Enhanced CLI
│   └── enhanced_cli.py        # Interactive CLI
├── core/                      # Core modules
│   └── advanced_tests.py      # Advanced testing
├── examples/
│   └── config.yaml            # Example configuration
├── requirements.txt           # Python dependencies
├── LICENSE                    # MIT License
└── README.md                  # This file
```

---

## 🛠️ Technologies Used

| Technology | Purpose |
|------------|---------|
| **Python 3.9+** | Core programming language |
| **Requests** | HTTP client for API calls |
| **Flask** | Web framework for dashboard |
| **Chart.js** | Interactive charts |
| **GraphQL** | API query language |
| **Docker** | Containerization for DVGA |
| **Concurrent.futures** | Multi-threaded scanning |

---

## ⚠️ Limitations

| Limitation | Explanation |
|------------|-------------|
| **Mutations Only** | Currently tests only mutations, not queries |
| **Introspection Dependency** | Requires introspection to be enabled |
| **Heuristic Error Detection** | Relies on substring matching for auth errors |
| **Generic Argument Values** | May cause schema validation errors |
| **No Object-Level Testing** | Does not test BOLA (object-level authorization) |

---

## 🚀 Future Improvements

- [ ] Add query field testing
- [ ] Resolve nested input objects recursively
- [ ] Add IDOR (Broken Object Level Authorization) testing
- [ ] Add rate limiting for production-safe scanning
- [ ] Integrate with Burp Suite
- [ ] Add support for OAuth scopes
- [ ] Generate PDF reports
- [ ] Add Slack/Email notifications
- [ ] Add historical scan comparison
- [ ] Implement role-based testing

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Your Name**

- GitHub: [@measwincm](https://github.com/measwincm)
- LinkedIn: [Aswin C.M](https://www.linkedin.com/in/aswin-cm/)

---

## 🙏 Acknowledgments

- [DVGA](https://github.com/dolevf/DVGA) for the vulnerable test target
- [OWASP](https://owasp.org/) for API Security guidelines
- [GraphQL](https://graphql.org/) community for introspection support

---

## ⭐ Support

If you found this project useful, please give it a **star** ⭐ on GitHub!

---

## 📊 Project Status

```
┌─ PROJECT COMPLETE ─────────────────────────────────────────┐

  GraphQL API Authorization Fuzzer · v4.0

  ● Production Ready
  ● CLI        ● Dashboard        ● Reports
  ● 5 CRITICAL vulnerabilities discovered in DVGA

  GitHub · Resume · LinkedIn · Security Assessments

└─────────────────────────────────────────────────────────────┘
```

---

**Made with ❤️ for API Security**

