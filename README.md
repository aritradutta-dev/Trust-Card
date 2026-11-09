# Trust Card: Intelligent Web Trust & Threat Analysis Platform

Trust Card is a privacy-first platform that detects phishing, malicious infrastructure, fraudulent payment links, fake recruitment portals, and certificate trust weaknesses by synthesizing threat intelligence, deep TLS inspection, static web security auditing, and collaborative threat sharing.

Its core differentiator is the **Context-Aware Trust Card**: it combines client-side message cues, local threat feeds, brand lookalike algorithms, and consent-gated live server inspection into a 7-pillar risk breakdown and deterministic, explainable verdict. **Raw message text never leaves the browser.**

---

## Quick Start

### Option A: Local Development with `uv`

1. Ensure Python 3.10+ and [uv](https://docs.astral.sh/uv/) are installed.
2. Install dependencies:
   ```bash
   uv sync --extra test
   ```
3. Seed the local demo threat data (contains safe test URLs, no real phishing):
   ```bash
   uv run python scripts/seed_demo.py
   ```
4. Start the application:
   ```bash
   ADMIN_USERNAME=admin ADMIN_PASSWORD=adminsecret uv run uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```
5. Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser.

---

### Option B: Production-Grade Isolation with Docker Compose

1. Copy `.env.example` to `.env` and generate strong random tokens:
   ```bash
   cp .env.example .env
   # Set ADMIN_USERNAME, ADMIN_PASSWORD, SCANNER_TOKEN, and SHARING_KEY
   ```
2. Validate Compose configuration:
   ```bash
   docker compose config --quiet
   ```
3. Start the isolated app and scanner containers:
   ```bash
   docker compose up --build -d
   ```
4. Seed demo data inside the container:
   ```bash
   docker compose exec web python scripts/seed_demo.py
   ```
5. Open [http://127.0.0.1:8000](http://127.0.0.1:8000).

---

## Demo Script & "Try an Example"

Trust Card provides one-click test chips directly on the homepage for quick demonstration:

- `http://demo-phish.trustcard.test/login`: Pre-seeded demo threat URL $\to$ **Known threat** (with clear badge: "Demo data, not real threat intelligence").
- `https://expired.badssl.com/`: Expired SSL certificate $\to$ **Caution: technical problems found** with prominent warning banner and parsed leaf details.
- `https://self-signed.badssl.com/`: Self-signed certificate $\to$ **Caution** (never labelled phishing).
- `https://wrong.host.badssl.com/`: Hostname mismatch $\to$ **Caution** with SAN mismatch details.
- `https://untrusted-root.badssl.com/`: Untrusted CA root $\to$ **Caution**.
- `https://example.com/`: Clean baseline website $\to$ **No strong warning found**.

Run the interactive presentation flow in [docs/DEMO.md](file:///Users/aritrad12/Trust Card/docs/DEMO.md) for a full 4-minute judge walkthrough.

---

## Threat Intelligence Providers

Trust Card supports three automated, consent-gated threat providers:
1. **OpenPhish** (Community feed): Fully functional out-of-the-box with **zero API key required**.
2. **URLhaus** (Abuse.ch): Malware and suspicious distribution endpoints.
3. **PhishTank**: Verified crowdsourced phishing URLs.

Feed refreshes are strictly manual and consent-gated. Providers are contacted via hardcoded hostnames with same-host redirect guards; checked URLs and messages are **never** transmitted to threat providers.

---

## Technical Pillars & Features

| Security Pillar | Capabilities & Defenses |
| :--- | :--- |
| **1. Threat Intelligence** | Exact URL matching against PhishTank, URLhaus, OpenPhish, and local seed databases. |
| **2. URL & Impersonation** | Offline public-suffix extraction, Punycode/IDN homoglyph detection, brand lookalike typosquatting (`rn` $\leftrightarrow$ `m`, `0` $\leftrightarrow$ `o`), and Indian payment/banking targets (SBI, HDFC, ICICI, Paytm, PhonePe, BharatPe, BHIM, IRCTC). |
| **3. Page Content** | Static detection of cross-site password submission, plain HTTP password posting, form action targeting raw IPs or form builders, hidden login iframes, meta-refresh redirects, and script obfuscation. |
| **4. Certificate & Trust** | Validates validity periods, SAN hostname matching, flags MD5/SHA-1 signatures and RSA $< 2048$ bits. Performs small-prime trial division ($p < 10{,}000$) to catch weak RSA key generation (eMudhra incident theme) and flags CAs on the conservative watchlist (`ca_watchlist.json`). |
| **5. Certificate Transparency & RDAP** | Optional secondary consent allows querying `crt.sh` and `rdap.org` (hostname only) for newly issued certificates, CA churn, and domains $< 30$ days old. |
| **6. Web Security** | Audits HSTS ($\ge 15{,}552{,}000$s), CSP `unsafe-inline`, framing (`X-Frame-Options`), MIME sniffing (`nosniff`), Referrer-Policy, Permissions-Policy, insecure cookies, and outdated server software banners. |
| **7. Collaborative Intelligence** | Local report deduplication, host-level reputation ($\ge 2$ approved reports flag other host paths), optional auto-approval threshold, and HMAC-SHA256 signed cross-instance export/import. |

---

## Design Choices & Invariants

- **Offline Public Suffix List**: We bundle a vendored snapshot (`app/data/public_suffix_list.json`) derived from Mozilla's Public Suffix List. Registrable domain calculations (e.g. `bank.co.in` vs `google.com`) run entirely offline with zero network lookups.
- **Optional CT & RDAP Consent**: Sending target hostnames to `crt.sh` or `rdap.org` requires a separate, explicit checkbox in the consent modal. Hostname only is sent; path and query are never transmitted.
- **Never "Safe"**: Trust Card never outputs the word "safe" for checked links. A clear scan produces "No strong warning found" with an explicit disclaimer that clean feeds do not prove legitimacy.
- **Deterministic Precedence**: The 7-pillar risk score ($0$–$100$) serves as an explanation aid. As documented in [docs/SCORING.md](file:///Users/aritrad12/Trust Card/docs/SCORING.md), indicator scores never override the deterministic verdict rules.

---

## Honest Limitations

1. **No JavaScript Execution**: Trust Card does not execute client-side JavaScript or simulate browser DOM rendering. This is an intentional security boundary to prevent sandbox escapes, drive-by downloads, and remote code execution against the scanner.
2. **Single-Page Bounded Scope**: The scanner follows public HTTP redirects up to 5 hops, but does not spider or crawl entire websites.
3. **Heuristics Are Not Ground Truth**: Brand similarity and homoglyph detection flag suspicious structural patterns, but cannot replace official trademark registry records.
4. **Offline CA Watchlist**: The CA watchlist is an offline review registry, not an automated revocation authority (OCSP/CRL), avoiding soft-fail network bypasses.
5. **Third-Party Availability**: `crt.sh` is an external free service that can occasionally experience latency or rate-limiting.

---

## Testing & Verification

Run the comprehensive test suite (120+ tests passing):

```bash
# Run Python backend unit tests
uv run --extra test python -m unittest discover -s tests -v

# Run Node.js client-side unit tests
node --test tests/context.test.mjs

# Validate Docker Compose configuration
docker compose config --quiet
```
