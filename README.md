# 🔍 GraphQL API Authorization Fuzzer

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-VAPT-red.svg)](https://owasp.org/)
[![GraphQL](https://img.shields.io/badge/GraphQL-API-purple.svg)](https://graphql.org/)

> Automated GraphQL API security testing tool that detects Broken Function Level Authorization (BFLA) vulnerabilities by testing restricted tokens against mutations.

---

## 📖 Table of Contents

- [Overview](#overview)
- [Why This Project](#why-this-project)
- [How It Works](#how-it-works)
- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Command Line Options](#command-line-options)
- [Sample Output](#sample-output)
- [Reports](#reports)
- [Project Structure](#project-structure)
- [Results](#results)
- [Technologies Used](#technologies-used)
- [Skills Demonstrated](#skills-demonstrated)
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
Most APIs check authentication (is the user logged in?) carefully, but often fail to check **authorization** (is this specific user allowed to run this specific action?). This gap is a well-known vulnerability class called **Broken Function Level Authorization (BFLA)**, catalogued as **CWE-285**.

### Real-World Impact
- **CVE-2025-11340**: GitLab's read-only tokens could execute write mutations
- **OWASP API Security Top 10**: #5 - Broken Function Level Authorization
- **Companies using GraphQL**: GitHub, Shopify, Netflix, Meta
- **GraphQL adoption growing 30% year-over-year**

### Why This Tool Matters
- Automates manual security testing
- Reduces human error
- Generates audit-ready reports
- Can be integrated into CI/CD pipelines

---

## ⚙️ How It Works

### Phase 1: Schema Discovery
The tool uses GraphQL introspection to automatically discover all mutations:

```graphql
query {
  __schema {
    mutationType {
      fields {
        name
        args {
          name
          type {
            name
            kind
          }
        }
      }
    }
  }
}
```

### Phase 2: Intelligent Input Generation
For each mutation, the tool generates test inputs based on argument types:

| Type | Test Value | Purpose |
|------|-----------|---------|
| String | `"authz-fuzzer-probe"` | Traceable test data |
| Int | `999999999` | Non-existent ID |
| Boolean | `false` | Minimum privilege |
| ID | `"999999999"` | Non-existent resource |

### Phase 3: Response Classification

| Response | Classification | Severity | Meaning |
|----------|---------------|----------|---------|
| ✅ SUCCESS | CRITICAL | 🔴 High | Token bypassed authorization! |
| ❌ Auth Error | SECURE | 🟢 Low | Token properly blocked |
| ❌ Schema Error | INFO | ⚪ Info | Invalid test data |
| 🔓 Public Endpoint | PUBLIC | ⚪ Info | Intentionally open |

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Schema Discovery** | Automatically discovers all mutations via GraphQL introspection |
| 🧪 **Intelligent Input** | Creates valid test inputs based on argument types |
| 📊 **Response Classification** | Categorizes results into CRITICAL, HIGH, SECURE, and INFO |
| 📄 **Multiple Reports** | HTML (interactive dashboard), JSON (CI/CD), CSV (Excel) |
| 🎨 **Professional HTML Report** | Interactive report with authorization boundary diagrams |
| 🔄 **Concurrent Testing** | Multi-threaded for fast execution |
| ⚙️ **CLI Interface** | Full command-line configuration |
| 🛡️ **False-Positive Reduction** | Public mutation allowlist and baseline token verification |
| 📦 **Lightweight** | Minimal dependencies (only `requests` library) |

---

## 🚀 Quick Start

### Prerequisites

```bash
# Python 3.9+
python3 --version

# Docker (for DVGA target)
docker --version

# Install dependencies
pip install requests
```

### Step 1: Start DVGA Container

```bash
docker run -d -t -p 5013:5013 -e WEB_HOST=0.0.0.0 --name dvga dolevf/dvga
```

### Step 2: Get Authentication Token

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

### Step 3: Run the Fuzzer

```bash
python3 graphql_authz_fuzzer.py \
  --url http://localhost:5013/graphql \
  --token "$(cat htoken.txt)" \
  --public-mutations "login,createUser" \
  --html-out report.html \
  --json-out report.json \
  --csv-out report.csv
```

### Step 4: View Reports

```bash
# Open HTML report
firefox report.html

# View JSON
cat report.json | python3 -m json.tool

# View CSV
cat report.csv
```

---

## 📦 Installation

### Clone the Repository

```bash
git clone https://github.com/yourusername/graphql-authz-fuzzer.git
cd graphql-authz-fuzzer
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

### Basic Command

```bash
python3 graphql_authz_fuzzer.py \
  --url <GRAPHQL_ENDPOINT> \
  --token <RESTRICTED_TOKEN> \
  --public-mutations "login,createUser"
```

### With Baseline Token (Recommended)

```bash
python3 graphql_authz_fuzzer.py \
  --url <GRAPHQL_ENDPOINT> \
  --token <RESTRICTED_TOKEN> \
  --baseline-token <PRIVILEGED_TOKEN> \
  --public-mutations "login,createUser" \
  --html-out report.html \
  --json-out report.json \
  --csv-out report.csv
```

---

## ⚙️ Command Line Options

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--url` | ✅ Yes | - | GraphQL endpoint URL |
| `--token` | ✅ Yes | - | Restricted/low-privilege token |
| `--baseline-token` | ❌ No | - | Privileged token for cross-check |
| `--public-mutations` | ❌ No | `""` | Comma-separated public mutations |
| `--timeout` | ❌ No | `8` | Request timeout in seconds |
| `--retries` | ❌ No | `1` | Retry count on connection errors |
| `--workers` | ❌ No | `4` | Concurrent request threads |
| `--html-out` | ❌ No | `report.html` | HTML output path |
| `--json-out` | ❌ No | `report.json` | JSON output path |
| `--csv-out` | ❌ No | `report.csv` | CSV output path |
| `--verbose` | ❌ No | `False` | Verbose output |

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

📄 Reports: report.html, report.json, report.csv
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
graphql-authz-fuzzer/
├── graphql_authz_fuzzer.py    # Main fuzzer script
├── htoken.txt                 # Authentication token
├── report.html                # HTML report
├── report.json                # JSON report
├── report.csv                 # CSV report
├── requirements.txt           # Python dependencies
├── LICENSE                    # MIT License
├── .gitignore                 # Git ignore file
└── README.md                  # This file
```

---

## 📊 Results

### Tested Against DVGA

| Mutation | Classification | Severity |
|----------|---------------|----------|
| **createPaste** | SUCCESS | 🔴 **CRITICAL** |
| **editPaste** | SUCCESS | 🔴 **CRITICAL** |
| **deletePaste** | SUCCESS | 🔴 **CRITICAL** |
| **uploadPaste** | SUCCESS | 🔴 **CRITICAL** |
| **importPaste** | SUCCESS | 🔴 **CRITICAL** |
| **createUser** | SCHEMA_ERROR | ⚪ INFO |
| **login** | RESOURCE_ERROR | 🟠 HIGH |

### Summary

```
┌─────────────────────────────────────────────────────────────┐
│                    FINAL RESULTS                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Total Mutations Tested: 7                                 │
│                                                             │
│   🔴 CRITICAL: 5                                           │
│   🟠 HIGH:     1                                           │
│   🟢 SECURE:   0                                           │
│   ⚪ INFO:     1                                           │
│                                                             │
│   Vulnerability Type: BFLA (CWE-285)                        │
│   OWASP: API Security Top 10 - #5                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Technologies Used

| Technology | Purpose |
|------------|---------|
| **Python 3.9+** | Core programming language |
| **Requests** | HTTP client for API calls |
| **GraphQL** | API query language |
| **Docker** | Containerization for DVGA |
| **Concurrent.futures** | Multi-threaded scanning |

---

## 🏆 Skills Demonstrated

| Skill | How It's Demonstrated |
|-------|----------------------|
| **Python Development** | Built complete security tool from scratch |
| **API Security** | Tested GraphQL authorization mechanisms |
| **GraphQL Knowledge** | Introspection, mutations, schema parsing |
| **Vulnerability Assessment** | Identified 5 critical BFLA vulnerabilities |
| **Tool Building** | Created reusable security testing tool |
| **Professional Reporting** | HTML, JSON, CSV outputs |
| **Security Testing** | Automated authorization bypass testing |

---

## ⚠️ Limitations

| Limitation | Explanation |
|------------|-------------|
| **Mutations Only** | Currently tests only mutations, not queries |
| **Introspection Dependency** | Requires introspection to be enabled |
| **Heuristic Error Detection** | Relies on substring matching for auth errors |
| **Generic Argument Values** | May cause schema validation errors |
| **No Object-Level Testing** | Does not test BOLA (object-level authorization) |
| **Single-Target Scope** | One endpoint per run |

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

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Your Name**
- GitHub: [@measwincm](https://github.com/measwincm)
- LinkedIn: [Aswin C.M](https://in.linkedin.com/in/aswin-cm-1543aa37b)


---

## 🙏 Acknowledgments

- [DVGA](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) for the vulnerable test target
- [OWASP](https://owasp.org/) for API Security guidelines
- GraphQL community for introspection support

---

## ⭐ Support

If you found this project useful, please give it a star ⭐ on GitHub!

---

## 📊 Project Status

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│          ✅ PROJECT COMPLETE - 100% DONE                   │
│                                                             │
│   GraphQL API Authorization Fuzzer                          │
│   Version: 3.0                                              │
│   Status: Production Ready                                  │
│   Findings: 5 CRITICAL Vulnerabilities                      │
│   Reports: HTML ✅ JSON ✅ CSV ✅                         |
│                                                             │
│   Ready for:                                                │
│   - GitHub                                                  │
│   - Resume                                                  │
│   - LinkedIn                                                │
│   - Interviews                                              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

**Made with ❤️ for API Security**


---



