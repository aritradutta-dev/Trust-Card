# Trust Card: 4-Minute Judge Demo Script

This document provides a click-by-click guide for demonstrating Trust Card to hackathon judges.

---

## Pre-Demo Setup (30 Seconds)

1. Ensure the app is running:
   ```bash
   ADMIN_USERNAME=admin ADMIN_PASSWORD=adminsecret uv run uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```
2. Ensure demo feed data is seeded:
   ```bash
   uv run python scripts/seed_demo.py
   ```
3. Open browser to `http://localhost:8000` with **Developer Tools $\to$ Network tab** open.

---

## Flow 1: Client-Side Privacy & Brand Impersonation (45 Seconds)

**Objective**: Prove zero-knowledge browser privacy and instant local detection of brand impersonation.

1. **What to paste into the input area**:
   ```text
   Urgent: Your SBI account is suspended. Verify UPI KYC payment immediately to avoid penalty: https://sbi-login.account-verify.in/kyc
   ```
2. **What happens immediately**:
   - Notice the browser automatically identifies the link and detects two context cues: `Urgency` and `Payment request`.
3. **Click `Check this link locally`**:
   - **Result**: Instant verdict $\to$ **Suspicious** (Confidence: High).
   - Point out the evidence panel:
     - `Lookalike of State Bank of India (SBI)` (Group: `url_lookalike`, Severity: `medium`).
     - `The message refers to a payment, fee, deposit, or transfer` (Group: `message_context`, Severity: `medium`).
     - Combining two independent medium groups deterministically results in **Suspicious**.
4. **Show Network Tab in DevTools**:
   - Inspect the request payload sent to `/api/v1/analyze`:
     ```json
     {
       "url": "https://sbi-login.account-verify.in/kyc",
       "mode": "local",
       "context_flags": ["urgency", "payment_request"]
     }
     ```
   - **Say to Judges**:
     > *"Notice that the raw message text never left the browser memory. Only the selected URL and privacy-preserving boolean category flags were transmitted."*

---

## Flow 2: BadSSL Certificate Failure & Caution Banner (45 Seconds)

**Objective**: Demonstrate deep TLS validation, certificate failure handling, and non-verifying fallback inspection without false phishing labels.

1. **Action**:
   - Click the chip **`https://expired.badssl.com/`** in the "Try an example" row.
2. **Click `Run live check`**:
   - The consent modal opens. Show judges that all planned outbound operations and safety limits are explicitly stated.
   - Click **`Allow this check`**.
3. **What to point out on the Trust Card**:
   - **Verdict**: **`Caution: technical problems found`** (with prominent amber `⚠` icon).
   - **Banner**: An eye-catching amber warning:
     > *"Certificate problem detected: This site has a certificate validation or trust failure. Never enter credentials or sensitive details on a site with certificate problems."*
   - **Say to Judges**:
     > *"Notice the system does not reassuringly say 'No warning found', but it also does not falsely cry 'Phishing' for an expired certificate. It assigns a dedicated Caution state."*
4. **Click `Certificate details` accordion**:
   - Expand the collapsible section to show the fully parsed X.509 leaf certificate: Subject, Issuer, SANs, Validity dates, Key type/size (RSA 2048), Signature algorithm, and SCT count.

---

## Flow 3: Seeded Threat Feed Match (30 Seconds)

**Objective**: Demonstrate instant threat feed correlation with clear provenance.

1. **Action**:
   - Click the chip **`http://demo-phish.trustcard.test/login`**.
   - Click **`Check this link locally`**.
2. **What to point out**:
   - **Verdict**: **`Known threat`** (Confidence: High, red `!` badge).
   - Finding: *"This exact URL appears in the Demo data, not real threat intelligence threat list."*
   - Next steps advise: *"Do not open this link or enter any personal details."*

---

## Flow 4: Collaborative Reporting & Admin Review Lifecycle (60 Seconds)

**Objective**: Demonstrate the complete crowd-sourced intelligence lifecycle from user report to admin approval.

1. **Submit a Community Report**:
   - Click chip **`https://example.com/`** and click **`Check this link locally`**.
   - Under the card, in the Report dropdown, select **`Impersonation`** (notice the button was disabled until a category was selected).
   - Click **`Report this link`**.
   - Toast notification: *"Thanks. This report is unverified until a local administrator reviews it."*
2. **Show Unverified State**:
   - Click **`Check this link locally`** again.
   - Under the Community Intelligence pillar, point out:
     > *"Reported 1 times locally, awaiting review"* (Severity: `low`).
     The link remains `no_strong_warning` because unverified reports never change verdicts alone.
3. **Review in Admin Console**:
   - Navigate to `/admin/reports` (Authenticate: `admin` / `adminsecret`).
   - Show the unverified report for `example.com` with its category, host, report count, and indicator fingerprint.
   - Click **`Approve`**.
4. **Re-check the Link**:
   - Return to `http://localhost:8000` and check `https://example.com/` again.
   - **Verdict**: Instantly escalates to **`Known threat`** because an administrator verified the community report!

---

## Flow 5: Certificate Transparency & Domain Age Lookups (30 Seconds)

**Objective**: Highlight external trust infrastructure monitoring with explicit secondary consent.

1. **Action**:
   - Enter `https://example.com/` and click **`Run live check`**.
2. **Point out the Consent Checkbox**:
   - Highlight the secondary checkbox:
     > *"Include third-party Certificate Transparency and domain age lookups (crt.sh and rdap.org)"*
   - Check the box and click **`Allow this check`**.
3. **Explain to Judges**:
   - The scanner performs a hostname-only lookup to `crt.sh` and `rdap.org` (never sending path or query secrets).
   - It verifies domain registration age (flagging newly minted domains $< 30$ days old) and detects sudden certificate authority churn.

---

## Flow 6: 7-Pillar Breakdown & Indicator Score vs. Verdict (30 Seconds)

**Objective**: Show the holistic multi-pillar architecture and explain the scoring philosophy.

1. **Inspect the Security Pillars Breakdown**:
   - Scroll through the 7 distinct pillars on the Trust Card:
     1. **Threat Intelligence** (PhishTank, URLhaus, OpenPhish)
     2. **URL & Impersonation** (Homoglyphs, Levenshtein edit distance, swap rules)
     3. **Page Content** (Static forms, password destinations, iframes)
     4. **Certificate & Trust** (Validity, RSA $< 2048$, weak key trial division, CA watchlist)
     5. **Web Security** (HSTS, CSP, XFO, outdated software banners)
     6. **Community Intelligence** (Local verified reports, peer sharing)
     7. **Message Context** (Urgency, credential, payment cues)
2. **Explain the Scoring Philosophy**:
   > *"Notice the metric 'Risk indicators: N/100 across 7 of 7 checks'. This provides users and analysts with transparent, explainable ranking. However, our architecture ensures that deterministic safety rules always govern the verdict: a website missing modern HTTP headers might score 15/100 on risk indicators, but it will never be falsely branded a Known Threat."*
