# Trust Card Public Check API

Trust Card exposes a clean, privacy-preserving HTTP API for automated security checks, chat bots, mail gateways, and security operations tools.

The platform's primary check endpoint is:
`POST /api/v1/analyze`

---

## Privacy Invariants

1. **No Raw Message Text**: The API strictly forbids raw message or email text. Any payload containing a `message` field is rejected (`422 Unprocessable Entity`).
2. **Deterministic Privacy Controls**: URL path, query strings, and secrets are stripped before threat indicators are fingerprinted or recorded.
3. **Explicit Consent Levels**:
   - `mode: "local"`: Purely offline lookup (threat intelligence, URL impersonation, community reports). Zero outbound traffic.
   - `mode: "full_scan"` with `consent: true`: Live TLS handshake and page inspection to the pinned destination IP.
   - `ct_rdap_consent: true`: Optional secondary permission to query Certificate Transparency logs (`crt.sh`) and domain registration records (`rdap.org`). Hostname only; never path or query.

---

## Endpoints

### 1. Local-Only Analysis (Zero Outbound Network)

Performs canonicalization, threat feed matching, brand lookalike/homoglyph detection, structural anomaly analysis, and community reputation lookups locally.

```bash
curl -s -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/login",
    "mode": "local",
    "context_flags": ["credential_request"]
  }' | jq
```

**Parameters**:
- `url` (string, required): The URL to evaluate (HTTP or HTTPS, max 2048 chars).
- `mode` (string, required): `"local"` for local-only analysis.
- `context_flags` (list of strings, optional): Cues detected locally by client (`"urgency"`, `"credential_request"`, `"payment_request"`, `"personal_data_request"`).

---

### 2. Consented Live Security Scan

Connects to the target web server using an isolated scanner with DNS re-pinning, validates TLS certificate chains, inspects HTTP security headers, and analyzes page content (cross-site password posts, deceptive iframes).

```bash
curl -s -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/",
    "mode": "full_scan",
    "consent": true
  }' | jq
```

**Parameters**:
- `url` (string, required): The target URL.
- `mode` (string, required): `"full_scan"`.
- `consent` (boolean, required): Must be `true` to authorize live connection.

---

### 3. Consented Live Scan with Certificate Transparency & RDAP Lookups

Enables additional third-party queries to Certificate Transparency logs (`crt.sh`) and domain registration data (`rdap.org`) to check for newly issued certificates, CA churn, and domain registration age (< 30 days).

```bash
curl -s -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/",
    "mode": "full_scan",
    "consent": true,
    "ct_rdap_consent": true
  }' | jq
```

---

## Response Structure

```json
{
  "scan_id": "97e682d334ff4441b80459c3bc82be72",
  "verdict": "suspicious",
  "confidence": "high",
  "coverage": "full",
  "scan_coverage": "full",
  "live_scan_complete": true,
  "scoring": {
    "score": 65,
    "summary": "Risk indicators: 65/100 across 7 of 7 checks",
    "checked_count": 7,
    "total_pillars": 7,
    "pillars": {
      "threat_intelligence": { "status": "clear", "score": 0, "why": "..." },
      "url_and_impersonation": { "status": "alert", "score": 80, "why": "..." },
      "page_content": { "status": "clear", "score": 0, "why": "..." },
      "certificate": { "status": "clear", "score": 0, "why": "..." },
      "web_security": { "status": "attention", "score": 15, "why": "..." },
      "community": { "status": "clear", "score": 0, "why": "..." },
      "message_context": { "status": "attention", "score": 60, "why": "..." }
    }
  },
  "findings": [
    {
      "id": "lookalike-brand-sbi",
      "category": "lookalike_domain",
      "severity": "medium",
      "group": "url_lookalike",
      "summary": "This domain resembles 'sbi' (edit distance 1) but is not an official domain.",
      "source": "Local URL & brand analysis",
      "observed_at": "2026-11-08T11:42:00Z"
    }
  ],
  "certificate": {
    "subject": "example.com",
    "issuer": "DigiCert Global Root G2",
    "sans": ["example.com", "www.example.com"],
    "valid_from": "2026-01-01T00:00:00Z",
    "valid_to": "2026-12-31T23:59:59Z",
    "key_type": "RSA",
    "key_size": 2048,
    "signature_algorithm": "sha256WithRSAEncryption",
    "sct_count": 2
  },
  "redirect_hosts": [],
  "feed_stale": false,
  "next_steps": [
    "Treat this link with caution.",
    "Do not enter passwords, payment details, or personal information."
  ]
}
```

---

## Verdict Values

| Verdict | Meaning |
| :--- | :--- |
| `known_threat` | Exact match in threat intelligence feeds, approved community report, or credential harvesting to third party. |
| `suspicious` | Two or more independent warning groups detected (e.g. brand lookalike + credential request context). |
| `caution` | Technical validation failures detected (e.g. expired or self-signed TLS certificate). |
| `no_strong_warning` | Completed scan found no known threats or high/medium risk signals. Never guarantees safety. |
| `not_enough_info` | Local-only check with stale or unpopulated threat intelligence. |
| `unable_to_check` | Target server unreachable, network connection timed out, or private IP blocked. |

---

## Administrative Endpoints

- `GET /api/v1/intel/status`: Threat feed freshness and entry counts.
- `POST /api/v1/intel/refresh`: Manually triggers fetch of configured threat feeds.
- `GET /api/v1/admin/reports?state={unverified|approved|rejected|all}`: Review submitted community reports (requires HTTP Basic Auth).
- `POST /api/v1/admin/reports/{id}/review`: Approve or reject reports.
- `GET /api/v1/admin/export`: Export approved threat reports signed with HMAC-SHA256 (`SHARING_KEY`).
- `POST /api/v1/admin/import`: Ingest signed threat intelligence reports from peer organizations into unverified review queue.

