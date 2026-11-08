# Risk Indicator Scoring and Explainability

Trust Card combines threat intelligence, URL analysis, live web security assessment, certificate validation, community reports, and message context into a unified evaluation.

In addition to the deterministic verdict (`known_threat`, `suspicious`, `caution`, `low_warning`, `no_warning`, or `not_enough_info`), Trust Card computes a transparent, weighted risk indicator score:

$$\text{Risk indicators: } N/100 \text{ across } X \text{ of 7 checks}$$

---

## Architectural Principles

1. **Deterministic verdicts are authoritative.**  
   The decision rules in `app/verdict.py` govern the user-facing verdict and safety advice. The risk score is an explanation and ranking aid; it **never** overrides verdict rules. For example, a website missing modern HTTP security headers may receive an indicator score of 15–25, but its verdict remains `no_warning` or `low_warning`—it is never escalated to `known_threat` or `suspicious` based on technical header findings alone.

2. **Explicit checked vs. unchecked transparency.**  
   Users and analysts always know which checks actually ran:
   - In a **local-only** evaluation (no outbound connection), `Page Content`, `Certificate & Trust`, and `Web Security` are explicitly marked:
     > *"Not checked (run a live scan)"*
   - When a link is checked without message context, `Message Context` is explicitly marked:
     > *"Not checked (paste the message that accompanied the link)"*
   - If threat feeds have not been downloaded or are stale, `Threat Intelligence` is marked:
     > *"Not checked (threat intelligence feeds missing or stale)"*

3. **Proportional rebalancing.**  
   Unchecked checks contribute 0 to the denominator. The score represents the weighted risk across **only the checks that were actually performed**.

---

## The 7 Security Pillars and Weights

| Pillar | Base Weight | Scope & Findings Evaluated | Status Values |
| :--- | :---: | :--- | :--- |
| **1. Threat Intelligence** | **35%** | Matches against PhishTank, URLhaus, OpenPhish, or local seed threat feeds. | `clear`, `alert`, `not_checked` |
| **2. URL & Impersonation** | **20%** | IDN/Punycode homoglyphs, brand typosquatting, brand-in-subdomain/path on unrelated domains, IP literals, `@` in authority, shorteners, suspicious TLDs. | `clear`, `attention`, `alert` |
| **3. Page Content** | **25%** | Cross-site password submission, plain HTTP password submission, form action to IP or form builder, hidden login iframes, meta-refresh redirects, obfuscated script markers. | `clear`, `attention`, `alert`, `not_checked` |
| **4. Certificate & Trust** | **15%** | Validity period, expiration, hostname match (SAN), self-signed, signature algorithm (MD5/SHA-1), RSA < 2048, weak key generation (small prime factor), CA watchlist. | `clear`, `attention`, `alert`, `not_checked` |
| **5. Community Intelligence** | **25%*** | Verified and unverified community reports submitted by local users and peer organizations. *\*Dynamic weight: 25% if reports exist; rebalanced to 0 if clear so unpopulated community data does not dilute threat indicators.* | `clear`, `attention`, `alert` |
| **6. Message Context** | **15%** | Urgency language, requests for passwords, OTPs, wire transfers, or identity data detected in the surrounding message. | `clear`, `attention`, `not_checked` |
| **7. Web Security** | **5%** | Missing HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), insecure cookies, outdated server software banners. | `clear`, `attention`, `not_checked` |

---

## Scoring Calculation

Each checked pillar receives a normalized subscore between $0$ and $100$:

- **Threat Intelligence**:
  - Exact match in confirmed threat feed: $100$ (`alert`)
  - Unconfirmed threat match: $50$ (`attention`)
  - Clear: $0$ (`clear`)
- **URL & Impersonation**:
  - Confirmed lookalike / homoglyph impersonation: $80$ (`alert`)
  - Medium structural anomaly or brand keyword on unrelated domain: $50$ (`attention`)
  - Minor URL anomaly: $25$ (`attention`)
  - Clear: $0$ (`clear`)
- **Page Content**:
  - High-severity credential harvesting or deceptive destination: $90$ (`alert`)
  - Medium-severity form destination / iframe / redirect: $55$ (`attention`)
  - Low-severity script obfuscation marker: $20$ (`attention`)
  - Clear: $0$ (`clear`)
- **Certificate & Trust**:
  - Certificate validation failure, weak key generation, or CA watchlist match: $75$ (`alert`)
  - Low technical finding (expiring soon, long validity, missing CT): $25$ (`attention`)
  - Clear: $0$ (`clear`)
- **Community Intelligence**:
  - Approved community report: $100$ (`alert`)
  - Unverified community report: $35$ (`attention`)
  - Clear (no reports): $0$ (`clear`)
- **Message Context**:
  - High-risk credential / payment / personal data request: $60$ (`attention`)
  - Urgency / pressure cues: $25$ (`attention`)
  - Clear: $0$ (`clear`)
- **Web Security**:
  - Outdated software banner: $30$ (`attention`)
  - Missing security headers: $\min(20, N \times 5)$ (`attention`)
  - Clear: $0$ (`clear`)

### Overall Score Formula

Let $\mathcal{C}$ be the set of pillars with status $\neq \text{"not\_checked"}$.  
For each pillar $k \in \mathcal{C}$, let $w_k$ be its active weight:
- For `community`: $w_{\text{community}} = 25$ if community findings exist, else $0$ (so absence of community reports does not artificially deflate risk).
- For all other checked pillars: $w_k$ is the base weight.

The normalized overall risk score is:

$$\text{Overall Score} = \mathrm{round}\left(\sum_{k \in \mathcal{C}} \text{score}_k \times \frac{w_k}{\sum_{j \in \mathcal{C}} w_j}\right)$$

Clamped to $[0, 100]$.

The summary string is formatted as:
```text
Risk indicators: N/100 across X of 7 checks
```
where $X = |\mathcal{C}|$.

---

## Invariant Guarantees

1. **No Safe Guarantees**: A score of $0/100$ means "no risk indicators found across checked pillars", never "verified safe".
2. **Deterministic Precedence**: Verdict assignment in `decide_verdict()` does not depend on the score. Technical findings (e.g. missing HSTS or self-signed cert) will never trigger `known_threat`.

