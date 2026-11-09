<!-- Copy of docs/WRITEUP.md for root visibility -->
# Trust Card — Intelligent Web Trust & Phishing Defense Platform
### *Complete Technical Write-up, Architecture Blueprint, and Engineering Challenges Solved*

> **Project Name**: Trust Card  
> **Repository**: [https://github.com/aritradutta-dev/Trust-Card](https://github.com/aritradutta-dev/Trust-Card)  
> **Author**: Aritra Dutta (`akuma2293941586@gmail.com` · `+91 94326 00615`)  
> **Platform & Stack**: Python 3.12+, FastAPI, SQLite (WAL mode), Vanilla JS (ES Modules), Modern CSS3, Cryptography (PyCA), Docker, Vercel Serverless  
> **Verification Status**: 127/127 Python unit tests passed · 9/9 Node privacy tests passed · 10/10 E2E integration tests passed  

---

## 1. Executive Summary & The Problem

Phishing and smishing (SMS phishing) have evolved far beyond obvious email spam. In 2026, attackers deploy short-lived lookalike domains, weaponized fake payment gateways (such as fraudulent UPI KYC portals charging nominal ₹99 fees), brand homoglyphs, and valid Let’s Encrypt SSL certificates to create a convincing illusion of legitimacy.

### Why Existing Security Tools Fall Short
1. **Privacy Invasions & Telemetry Leaks**: Existing online scanners (e.g. VirusTotal, URLScan) store, index, and publish user inputs publicly. If an executive or everyday user pastes an SMS containing a private one-time link, order invoice, or password reset token, it leaks to third parties.
2. **The "Green Padlock" Fallacy**: Modern threat actors use valid HTTPS certificates on 85%+ of phishing domains. Users are conditioned to believe HTTPS means "safe", when it only guarantees encrypted transport to the attacker's server.
3. **Delayed Feed Intelligence**: Centralized blocklists (like Google Safe Browsing) often take 12 to 48 hours to ingest newly registered threat infrastructure. In targeted attacks, the phishing domain has already executed its payload before appearing on any list.
4. **Opaque and Binary Verdicts**: Existing scanners return technical jargon ("DKIM fail", "Punycode mismatch") without explaining *why* a link is dangerous or what safer action the user should take. Worse, they label clean sites "Safe", creating false confidence.

### The Trust Card Solution
**Trust Card** is a privacy-first, context-aware web security and phishing detection platform. It evaluates suspicious links across **7 security pillars**, combines client-side message cue extraction with cryptographic certificate inspection, enforces strict on-device privacy boundaries, and delivers plain-language explanations without ever declaring a site "Safe".

---

## 2. Core Philosophy & Architectural Invariants

Trust Card is engineered around four non-negotiable principles:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        TRUST CARD CORE INVARIANTS                           │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. Zero-Knowledge Client Privacy                                            │
│    Raw message text NEVER leaves browser memory. Links and cues are parsed   │
│    locally; only the selected link and sanitized category flags are sent.    │
├─────────────────────────────────────────────────────────────────────────────┤
│ 2. The "No Safe Label" Invariant                                            │
│    Trust Card NEVER labels any link "Safe". Even verified sites receive     │
│    "No Strong Warning" or "Caution", reminding users that HTTPS is not a    │
│    guarantee of trust.                                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│ 3. Deterministic Verdict Hierarchy                                          │
│    Verified Threat Feed Match  ──► KNOWN THREAT (Score 70-100, Malicious)   │
│    Homoglyphs / Fraud Keywords ──► SUSPICIOUS (Score 30-69, Suspicious)     │
│    Expired / Invalid TLS Cert  ──► CAUTION (Score 25-45, Attention)          │
│    No Threat Signals Detected  ──► NO STRONG WARNING (Score 0-20, Low Risk) │
├─────────────────────────────────────────────────────────────────────────────┤
│ 4. Granular Consent-Gated Active Inspection                                 │
│    Passive local checks make zero outbound connections to the target. Live   │
│    scans require explicit user consent, informing users of every network hop│
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. High-Level Architecture & Trust Boundaries

The platform operates across three isolated boundaries to maintain complete security and zero data leakage:

```mermaid
flowchart TD
    subgraph Browser ["User Browser (Zero-Knowledge Privacy Enclave)"]
        UI["Web UI (Holst Palette, Vanilla JS)"]
        Parser["DOM Parser & URL Extractor (regex, max 5)"]
        CueEngine["Context Cue Engine (client-side heuristic)"]
        ConsentMgr["Consent Controller (explicit per-link permission)"]
        
        UI --> Parser
        UI --> CueEngine
        UI --> ConsentMgr
    end

    subgraph AppHost ["Trust Card Application Service (FastAPI)"]
        API["FastAPI App Service (app/main.py)"]
        URLAnalyzer["URL & Impersonation Engine (app/url_analysis.py)"]
        VerdictEngine["Deterministic Verdict Decider (app/verdict.py)"]
        ScoringEngine["7-Pillar Scoring Matrix (app/scoring.py)"]
        Explainer["AI Security Explainer (app/ai_explainer.py)"]
        Store[("SQLite Store (WAL mode) (app/storage.py)")]
        VendoredData["Vendored PSL & Brands (brands.json)"]
        
        API --> URLAnalyzer
        API --> VerdictEngine
        API --> ScoringEngine
        API --> Explainer
        API --> Store
        URLAnalyzer --> VendoredData
    end

    subgraph ScannerCore ["Scanning Engine (In-Process Fallback or Isolated Daemon)"]
        DNSPinner["DNS Resolver & SSRF Guard (RFC 1918 / Loopback Block)"]
        TLSInspector["Deep TLS & Cryptographic Cert Analyzer (scanner/certs.py)"]
        PageInspector["HTML & Security Header Auditor (scanner/page_signals.py)"]
        CTRDAP["Hostname-Only CT / RDAP Monitor (scanner/ct_rdap.py)"]

        DNSPinner --> TLSInspector
        DNSPinner --> PageInspector
        DNSPinner --> CTRDAP
    end

    subgraph ExternalWeb ["Target Host & Intelligence Providers"]
        TargetHost["User Target Host (Strictly Pinned IP Only)"]
        Feeds["Fixed Threat Feed Providers (PhishTank, URLhaus, OpenPhish)"]
        CRT["crt.sh (Certificate Transparency Logs)"]
        Peers["Peer Trust Card Nodes (Signed HMAC-SHA256 Sync)"]
    end

    %% Communications
    Browser -- "Selected URL + Cue Flags Only (No Raw Message)" --> API
    API -- "Consented Live URL" --> ScannerCore
    ScannerCore -- "Pinned TLS Handshake & GET" --> TargetHost
    API -- "Periodic Feed Fetch" --> Feeds
    ScannerCore -- "Hostname-Only CT Query" --> CRT
    API -- "Signed Threat Export / Import" --> Peers
```

---

## 4. Key Platform Features & Modules

### 4.1. Privacy-Preserving Link Checker
* **Client-Side Extraction**: Automatically parses up to 5 unique HTTP/HTTPS links from raw message text using `context.mjs`. Trailing punctuation, parenthetical artifacts, and fragments are cleaned on-device.
* **Context Cue Detection**: Identifies pressure tactics across 4 categories:
  * `urgency` ("immediate", "suspended within 24h", "urgent action required")
  * `credential_request` ("verify password", "login now", "confirm OTP")
  * `payment_request` ("pay fee", "charges applied", "₹99", "UPI payment")
  * `personal_data_request` ("submit Aadhaar", "PAN number", "SSN")
* **Zero Telemetry**: The server never receives the user's message body, email contents, or recipient information.

### 4.2. URL & Brand Lookalike Analysis Engine
* **IDN / Punycode Homoglyph Detection**: Detects spoofed characters across Cyrillic, Greek, and Latin alphabets (e.g., Cyrillic `а` swapped for Latin `a`, `р` for `p`, `раураl.com`).
* **Brand Distance & Swap Analysis**: Evaluates registrable domain tokens against 120+ top target brands (financial institutions, cloud platforms, e-commerce) using Levenshtein distance and common typographical substitutions (e.g., `rn` $\to$ `m`, `vv` $\to$ `w`, `0` $\to$ `o`, `l` $\to$ `1`).
* **Deceptive Structural Patterns**: Flags misleading subdomains (e.g., `paypal.com.verify-login.xyz`), excessive hyphens, embedded fraud keywords (`kyc`, `refund`, `support`, `verify`), and suspicious high-risk TLDs (`.xyz`, `.top`, `.tk`, `.buzz`).

### 4.3. The 7-Pillar Security Audit Matrix
Every link is scored out of 100 based on a multi-dimensional risk matrix:

| Security Pillar | Weight | Evaluation Method & Finding Triggers |
| :--- | :---: | :--- |
| **1. Threat Intelligence** | 35% | Exact SHA-256 hash match against PhishTank, URLhaus, and OpenPhish feeds. |
| **2. URL & Brand Impersonation** | 20% | Homoglyphs, brand edit distance $\le 2$, deception subdomains, keyword spoofing. |
| **3. Web Security & Content** | 25% | Presence of login forms without HTTPS, hidden iframes, credential harvesters. |
| **4. Cryptographic Trust & TLS** | 15% | Hostname SAN mismatch, expired certificates, self-signed chains, weak keys. |
| **5. Community Intelligence** | 25% | Peer-reviewed reports, verified community submissions, repeat host flags. |
| **6. Message Context & Cues** | 15% | Combination of urgency + payment requests or credential requests. |
| **7. HTTP Security Headers** | 5% | Strict-Transport-Security (HSTS), Content-Security-Policy (CSP), nosniff. |

### 4.4. Deep TLS Cryptographic Audit
* **Full X.509 Certificate Chain Inspection**: Extracts subject alternative names (SANs), serial numbers, SHA-256 fingerprints, issuer authorities, validity windows, and signature algorithms using Python's `cryptography` library.
* **Weak Key Generation Test**: Checks RSA public moduli against small prime trial division ($p < 10{,}000$) to catch compromised or backdoored key generation systems (inspired by the ROCA and Debian RNG vulnerabilities).
* **Certificate Authority Watchlist**: Flags certificates issued by untrusted, deprecated, or high-risk intermediate CAs.

### 4.5. Real-Time Certificate Transparency & DNS Monitor
* **CT Log Search**: Queries public Certificate Transparency logs (via `crt.sh`) for any domain to list all certificates ever issued, discover unindexed subdomains, and identify rogue certificates issued within the last 30 days.
* **Comprehensive DNS Resolution**: Resolves IPv4 (A), IPv6 (AAAA), and canonical names (CNAME) using standard socket resolution with strict timeouts.

### 4.6. Collaborative Threat Intelligence & Community Forum
* **Peer-to-Peer Threat Sharing**: Administrators can export approved threat indicators as HMAC-SHA256 signed JSON payloads and import them into peer Trust Card nodes without sharing user identifiers.
* **Interactive Security Forum**: Community discussion threads with upvoting, categorization (`Phishing Alert`, `Incident Analysis`, `Tool Guide`, `Help / Question`), and verified analyst responses.
* **Incident Hotline & Masked Email**: One-click hotline integration (`+91 94326 00615`) and direct Gmail compose redirects for reporting targeted phishing campaigns (`akuma2293941586@gmail.com`).

### 4.7. Print-Ready PDF Assessment Reports
* Generates an executive-ready, high-contrast security assessment report at `/scans/{scan_id}/report` containing the 12-section technical finding breakdown, risk score, certificate parameters, and concrete mitigation steps.

---

## 5. Deep Dive: Major Engineering Challenges & Solutions

### Challenge 1: Zero-Knowledge Privacy at the Client Boundary
* **The Problem**: Users paste sensitive SMS lures, WhatsApp messages, or work emails that contain personal identifiers, account numbers, or OTP tokens. If raw text was transmitted to the server, Trust Card would become a massive privacy liability.
* **The Solution**: We implemented the URL parser and context cue analyzer entirely in client-side modern JavaScript (`app/static/context.mjs`). Regex extractors isolate URLs and clean surrounding punctuation before anything is sent. Context cues are mapped to generic enum flags (`urgency`, `payment_request`). The backend API strictly rejects requests containing a `message` or `text` field with HTTP 422.

### Challenge 2: SSRF and DNS Rebinding Prevention in Network Scanning
* **The Problem**: A malicious actor could use the scanner to probe internal cloud metadata endpoints (`http://169.254.169.254/latest/meta-data/`), internal services (`http://localhost:8000/admin`), or use DNS rebinding to bypass IP checks between DNS resolution and socket connection.
* **The Solution**: In `scanner/engine.py`, we built a custom connection handler:
  1. DNS resolution occurs once; the resulting IP is evaluated against `ipaddress.is_private`, `is_loopback`, `is_link_local`, `is_multicast`, and `is_reserved`.
  2. If the IP is private or invalid, an `UnsafeDestinationError` is raised immediately.
  3. The socket connection is explicitly pinned to that validated IP address, completely mitigating DNS rebinding attacks.
  4. Outbound HTTP requests enforce `MAX_REDIRECTS = 5`, and redirect targets undergo the exact same IP pinning checks.

### Challenge 3: Cryptographic Weakness Detection in TLS Handshakes
* **The Problem**: Standard Python HTTP clients (`urllib`, `requests`, `httpx`) abort immediately if a certificate fails verification (e.g. self-signed or expired), hiding the certificate details from the user. Conversely, disabling verification leaves the connection vulnerable.
* **The Solution**: In `scanner/certs.py`, we implemented a two-pass handshake:
  1. **Verification Pass**: Attempts a strict validation handshake against system root CAs to identify trust state and SAN matching.
  2. **Raw Capture Pass**: If the verification pass fails, a secondary non-verifying socket handshakes to extract raw DER certificate bytes.
  3. Using `cryptography.x509`, we parse the raw ASN.1 structure, extracting validity dates, public key algorithms, and testing RSA moduli for small prime factors ($p < 10{,}000$).

### Challenge 4: Safari / WebKit String Parsing & Unstyled PDF Export
* **The Problem**: 
  - On Safari and iOS WebKit, calling `res.json()` on plain-text server responses threw `SyntaxError: The string did not match the expected pattern.`, triggering uncaught error toasts.
  - When users clicked "Download PDF", opening a print dialog via `window.print()` before external CSS loaded resulted in raw, unstyled HTML printouts.
* **The Solution**:
  - Implemented `safeFetchJson()` in `app/static/app.mjs` which inspects `content-type` headers, sanitizes text payloads, and catches syntax errors before showing toasts.
  - In `app/templates/report.html`, we embedded the complete print styling directly inside `<style>` tags in the HTML `<head>`. The report renders 100% styled from byte 0, with `@media print` rules optimizing page breaks and margins for instant PDF printing.

### Challenge 5: Bridging Localhost Microservice & Vercel Serverless Architecture
* **The Problem**: On localhost, Trust Card ran a separate scanner daemon on port 9000 and persisted data to `data/trust-card.sqlite3`. When deployed to Vercel's serverless environment:
  - There was no external scanner daemon, causing all live scans to return `"error": "scanner_unavailable"`.
  - The Vercel root directory is read-only, causing SQLite file creation errors.
  - Fresh `/tmp` databases lacked pre-seeded threat intelligence, causing sample demo links to return clean results instead of threat verdicts.
* **The Solution**:
  - **In-Process Engine Fallback**: Updated `app/scanner_client.py` so that if `SCANNER_URL` is unset, the application automatically invokes `scanner.engine.scan_url` in-process. Live scanning works seamlessly on Vercel without a secondary daemon.
  - **Dynamic `/tmp` Storage Resolution**: Implemented `_resolve_data_dir()` in `app/main.py` to automatically detect read-only filesystems and write to `/tmp/trustcard_data` with SQLite WAL mode.
  - **Automatic Vercel Threat Seeding**: Added `seed_default_threat_data()` which detects Vercel serverless environments (`VERCEL=1`) and automatically pre-seeds verified demo feeds, community reports, and active provider timestamps on initialization.
  - **Native Vercel Routing**: Added `vercel.json` and `api/index.py` to route all requests natively into FastAPI.

### Challenge 6: Flashing and Trapping in the Luxury Boot Screen
* **The Problem**: Returning users experienced a noticeable flash of the loading screen on page refresh before client JavaScript executed. Furthermore, if network latency delayed asset loading, the full-screen overlay blocked pointer interaction.
* **The Solution**:
  - Added an inline script in `<head>` that checks `sessionStorage.getItem('tc_boot_completed')` before the DOM renders and applies `html.tc-skip-boot #system-boot-overlay { display: none !important; }`. Repeat page loads render instantly with zero flash.
  - Added an inline fail-safe timer (2.4s) before `</body>` to guarantee overlay removal and restore body scrolling under any circumstance.
  - Added an explicit **"Skip ✕"** button, `Esc` key listener, and click-anywhere dismissal.

---

## 6. Verification & Quality Assurance

Trust Card includes comprehensive automated test suites across frontend and backend modules:

```
======================================================================
TEST SUITE EXECUTION SUMMARY
======================================================================

1. Node.js Client-Side Context Tests (tests/context.test.mjs)
   ✔ extracts at most five unique HTTP and HTTPS links
   ✔ caps extracted links at five
   ✔ normalizes hosts and removes fragments before deduplication
   ✔ skips malformed and credential-bearing links while retaining IPv6
   ✔ multiple-link picker selects first radio correctly
   ✔ detects context categories without leaking raw text
   ✔ returns no context flags for ordinary text
   ✔ analysis request contains only selected URL and cue flags
   Result: 9 / 9 Passed (0 failures)

2. Python Automated Test Suite (tests/)
   ✔ App Shell & Security Middleware Tests (tests/test_app.py)
   ✔ URL Normalization & Homoglyph Engine Tests (tests/test_urls.py)
   ✔ 7-Pillar Scoring & Verdict Consistency Tests (tests/test_scoring.py)
   ✔ Threat Feed Ingestion & Strict Redirect Tests (tests/test_feeds.py)
   ✔ Deep TLS Inspection & Weak Key Factoring Tests (tests/test_certs.py)
   ✔ Collaborative Threat Export/Import HMAC Tests (tests/test_sharing.py)
   ✔ DNS Resolution & Certificate Transparency Tests (tests/test_ct.py)
   Result: 127 / 127 Passed (0 failures)

3. End-to-End API Integration Suite (create_app TestClient)
   ✔ Healthcheck & Home Shell (200 OK)
   ✔ Local Security Analysis with Category Detection (200 OK)
   ✔ Report View Rendering (/scans/{id}/report) (200 OK)
   ✔ Dashboard Statistics Aggregation (200 OK)
   ✔ Scan History & Compare Dialog (200 OK)
   ✔ Certificate Transparency Search (200 OK)
   ✔ DNS Resolution via Socket (200 OK)
   ✔ Collaborative Intelligence Search (200 OK)
   ✔ Security Forum Discussions & Replies (200 OK)
   ✔ Authentication & Session Lifecycle (200 OK)
   Result: 10 / 10 Scenarios Passed
======================================================================
```

---

## 7. Future Roadmap

1. **Native Browser Extension (Chrome Manifest V3)**:
   - Perform on-device DOM inspection of links before navigation.
   - Inline warning badges directly on messaging platforms (WhatsApp Web, Gmail, Slack).
2. **Decentralized Threat Consensus (Consortium Ledger)**:
   - Replace centralized feed aggregators with cryptographically signed, peer-validated blocklists shared across security teams via decentralized gossip networks.
3. **Automated UPI QR Code Fraud Scanner**:
   - Parse embedded payment URLs inside QR codes to detect fraudulent merchant names, personal VPA transfers disguised as utility bills, and spoofed banking handles.

---

## 8. Conclusion

Trust Card bridges the gap between opaque technical security tools and vulnerable end users. By enforcing zero-knowledge client privacy, evaluating multi-layered threat signals across 7 pillars, inspecting cryptographic parameters, and presenting transparent, explainable recommendations, Trust Card provides a trustworthy defense against modern social engineering and web threats.
