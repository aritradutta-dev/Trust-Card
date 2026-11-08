# Trust Card MVP — P0 Audit and Implementation Plan

**Status:** Audit complete; awaiting user review. No implementation is authorized by this plan until reviewed.

**Goal:** Bring the existing local-first Trust Card MVP into alignment with all P0 requirements in `docs/PRD.md`, preserving behavior that already complies.

**Sources reviewed:** `docs/PRD.md`, `README.md`, `app/`, `scanner/`, `tests/`, `compose.yaml`, Dockerfiles, and the extracted Stitch design guide/screens. The named ZIP was not present at its Downloads path; the project contains extracted Stitch assets. They are treated only as visual references.

## Audit Summary

The app already implements browser-side message parsing, local-only checks, consent-gated live scans, cached PhishTank and URLhaus data, administrator-reviewed local reports, explainable verdicts, and an isolated SSRF-aware scanner. Compose publishes only the web app on `127.0.0.1`; the scanner has no host-published port and uses separate internal and egress networks.

Three small behavior/copy gaps stand out:

1. The browser deduplicates using `URL.href` but submits the original candidate, so fragments, trailing-dot hostnames, and noncanonical host spelling reach the app; fragment variants can also appear as separate choices.
2. The multiple-link picker checks the first radio by default, so the user can proceed without actively choosing a link.
3. Redirect and password-form destination checks use a suffix-based “same site” comparison. The PRD says a different hostname is a signal, so a sibling hostname can currently be missed. The consent dialog also omits the explicit initial request count and total time budget.

Other behavior appears aligned by inspection. Several controls have focused unit coverage, but some security boundaries lack direct regression tests; those are listed in the plan rather than treated as known implementation defects.

## P0 Requirement Gap Table

| PRD requirement | Current evidence | Missing or uncertain behavior | Smallest proposed change |
|---|---|---|---|
| **FR-01 — Input** | `app/templates/index.html:44-52` has a labeled 12,000-character field and an announced error. `tests/test_app.py:test_home_page_has_a_plain_language_message_input` checks the input. | No identified behavior gap. | No product change. Keep the existing input and empty/error handling. |
| **FR-02 — Link extraction and normalization** | `app/static/context.mjs:1-24` extracts HTTP/S links, skips credentials, deduplicates, and caps at five. `app/urls.py:14-52` normalizes hostname, IDNA, trailing dot, default port, fragment, path, and query on the server. | The browser keys on `parsed.href` but returns the raw candidate. It does not strip fragments or trailing hostname dots before sending; fragment variants may be offered twice. Valid IPv6 URLs ending in `]` may be mistaken for trailing punctuation. | Normalize in `extractUrls` with the built-in `URL` parser, strip `.hash`, remove a final dot from `.hostname`, preserve valid IPv6 brackets, return/deduplicate the normalized URL, and preserve path/query. Add focused browser extraction cases. |
| **FR-03 — Message cues and privacy** | `app/static/context.mjs:4-9` detects urgency, credential, payment, and personal-data cues. `app/static/app.mjs:171` posts only `url`, `mode`, `consent`, and `context_flags`. `app/main.py:24-44` restricts flags and forbids extra request fields. `tests/test_app.py:test_api_rejects_raw_message_text` rejects a `message` field. | Code inspection shows no raw-message path. There is no browser integration test proving the request payload boundary. | No product change unless a focused request-payload check finds a gap. Add a check that the API accepts only the selected URL and supported flags, and rejects message text/unsupported flags. |
| **FR-04 — Local-only check** | `app/main.py:124-168` looks up cached exact URL hashes, approved/unverified local reports, and cue flags. `tests/test_app.py:test_local_check_does_not_call_the_scanner` checks that local mode makes no scanner call. | No identified behavior gap. | No product change. Preserve `local_only` coverage and the no-site-connection path. |
| **FR-05 — Per-link live consent** | `app/templates/index.html:112-127` defines a consent dialog. `app/static/app.mjs` fills the dialog from the selected URL and only approves through its button. `app/main.py:258-259` rejects a live scan without consent; `tests/test_app.py:test_full_scan_without_consent_never_calls_the_scanner` covers the API boundary. | The dialog says it connects and follows redirects but does not explicitly state one initial request or the scanner’s 20-second total budget. | Clarify the existing dialog: one read-only GET to the displayed URL, up to five GETs to public redirect destinations, the 20-second total budget, and the 2 MiB HTML limit. Keep per-link approval and decline behavior. |
| **FR-06 — Bounded live scan** | `scanner/engine.py:19-21` sets five redirects, 2 MiB, and 20 seconds. `_request_pinned` uses `GET` (`:350-405`); `scan_url` follows redirects (`:420-494`). | Existing tests cover a deadline reader but do not directly pin six-GET maximum, redirect cap, or body cap as end-to-end mocked scanner behavior. | No scanner change unless focused mocked checks fail. Add deterministic mocked HTTP/DNS tests for at most one initial request plus five redirects, byte cap, submitted scheme/port rules, and timeout. |
| **FR-07 — TLS and static web signals** | `scanner/engine.py:301-356` uses the system TLS context, reports certificate validation errors and certificates expiring within 14 days. `:250-297` statically inspects password forms; `:501-526` checks a small header set. | `_same_site` is suffix-based (`:102-106`) and is used for both form actions (`:294`) and redirects (`:483`). Related but distinct hostnames can be treated as the same site, contrary to the PRD’s different-hostname rule. | Replace the suffix check with an exact normalized-hostname comparison for these two PRD signals. Preserve system certificate validation and static-only page inspection. |
| **FR-08 — SSRF protections** | `scanner/engine.py:42-98` rejects non-global DNS answers, including a host if any answer is restricted. `:315` connects to the validated address. `scan_url` resolves every redirect target (`:430`). `tests/test_scanner.py:test_blocks_private_literal_and_private_dns_answers` checks private and mixed answers. | Redirect-to-loopback/metadata and re-resolution after redirect are not directly tested with mocked HTTP; implementation appears to revalidate before each request. | No change unless checks reveal a defect. Add mocked tests proving a restricted redirect is blocked before a second connection and every redirect gets fresh DNS validation. |
| **FR-09 — Verdict rules** | `app/verdict.py:7-27` prioritizes confirmed matches, marks incomplete scans unable, counts high signals and distinct medium groups, and excludes technical groups. `tests/test_verdict.py` covers high, two independent mediums, technical-only, known, incomplete, and stale confidence. | Existing stale-confidence assertion checks only that confidence is not high; it does not assert the PRD’s exact values for each verdict/freshness state. | No product change indicated. Add table-driven checks for exact verdict/confidence mappings, including stale/missing feeds and confirmed-match precedence. |
| **FR-10 — Evidence Trust Card** | `app/main.py:157-168, 266-291` returns verdict, confidence, coverage, times, evidence, redirect hosts, feed status, and next steps. `app/static/app.mjs:200-380` renders these fields. | No functional gap found. Visual reading of screen-reader and mobile behavior remains unverified in a browser. | No product change by inspection. Include keyboard/mobile review in final phase; adjust only if it exposes a P0 failure. |
| **FR-11 — Manual threat-feed refresh** | `app/templates/index.html:130-142` names PhishTank and URLhaus in a separate confirmation. `app/static/app.mjs:412` requests those providers only. `app/feeds.py:17-80` parses verified PhishTank and URLhaus data and records errors; `app/storage.py:57-90` swaps entries and records refresh errors. `app/main.py:67-90` marks feeds stale after 24 hours or an error. | Existing feed test proves a network fetch failure preserves the prior snapshot, but not that a syntactically invalid downloaded file preserves it. Exact 24-hour and error-state freshness boundaries are not directly tested. | No product change unless checks fail. Add invalid-payload rollback and feed-age/error status tests using fixtures only. Keep refresh manual and provider-scoped; never pass a checked URL to the feed fetcher. |
| **FR-12 — User reports** | `app/main.py:48-51, 231-255` accepts only scan ID/category and maps it to a query-free fingerprint and host. `app/storage.py:109-128` stores fingerprint, host, category, state, and timestamps. `tests/test_app.py:test_report_persists_only_query_free_fingerprint_and_stays_unverified` checks persistence. | `scan_sessions` is an in-memory, expiring link between a result and a report; it stores only fingerprint/host metadata, not a full scan history. This appears compatible, but deserves an explicit retention assertion. | No product change. Add a focused assertion that report persistence contains only approved fields and no raw URL, query, message, or findings. |
| **FR-13 — Admin report review** | `app/main.py:297-324` requires configured Basic authentication for report listing/review. `app/storage.py:127-166` stores review state; only approved reports are confirmed in `_local_result`. `tests/test_app.py:test_admin_approval_requires_credentials_and_affects_future_local_check` covers the workflow. | No identified behavior gap. | No product change. Preserve authenticated review and unverified-by-default behavior. |
| **FR-14 — Accessible responsive UI** | `app/templates/index.html` associates labels, announces errors/results, uses a native radio group and dialog. `app/static/styles.css` has responsive breakpoints, focus-visible styles, and reduced-motion handling. Verdicts include text and icons, not color alone. | First link is preselected (`app/static/app.mjs:129`); keyboard/mobile layout and contrast have not been verified in a real browser. | In Phase 1, leave all link radios unselected until the user chooses. In final checks, verify keyboard choice, focus, dialog decline, mobile width, and readable contrast; change CSS only for an observed P0 defect. |

## Existing Checks Reviewed

- `node --test tests/context.test.mjs`: existing checks for five-link cap, duplicate simple URLs, punctuation removal, and cue categories.
- Python `unittest`: existing checks for local versus live mode, consent enforcement, feed refresh, report privacy/admin approval, scanner DNS safety, deadlines, URL normalization, and verdict groups.
- `compose.yaml`: web host port bound to `127.0.0.1`; web and scanner are separated; scanner has no published host port; outbound scanning uses a separate egress network.
- No Docker or live provider/site check was run as part of this audit. The baseline Node and Python suites were run before the request changed to audit-only; they passed (4 Node tests and 36 Python tests). `uv run` could not initialize its host cache due filesystem permissions, so the existing project virtual environment was used directly.

## Phased Implementation Plan

### Phase 1 — Canonical browser links and explicit link choice

**Likely files:** `app/static/context.mjs`, `app/static/app.mjs`, `tests/context.test.mjs`.

**Change:** Return normalized browser URLs after clearing fragments and removing a trailing hostname dot; deduplicate by normalized URL. Keep path/query, IDNA normalization, lowercasing, and default-port removal. Do not preselect a link when multiple links are found; retain the existing no-selection guard.

**Focused checks:** Add Node tests for IDNA/lowercase, trailing dot, default ports, fragments and deduplication, path/query preservation, credential URLs, malformed input, and IPv6 URL extraction. In a browser, paste two links and verify there is no initial selection and no analyze request before selecting one; verify the selected normalized URL is the one sent.

**Security risks:** A fragment or query must not be lost/changed incorrectly: fragments are excluded; queries remain for exact feed lookup and must not be logged or stored. The raw message must stay in the browser. Avoid breaking valid bracketed IPv6 URLs while trimming surrounding punctuation.

### Phase 2 — Exact hostname evidence and scanner boundary checks

**Likely files:** `scanner/engine.py`, `tests/test_scanner.py`.

**Change:** Replace `_same_site` with an exact normalized-hostname comparison for redirects and password-form destinations. Do not change redirect-following, TLS, or connection-pinning architecture.

**Focused checks:** Add mocked HTTP/DNS cases for sibling-host redirect/form signals, same-host form behavior, redirect to loopback/metadata, mixed DNS answers, and DNS revalidation after redirects. Assert no request reaches a restricted address. Pin the maximum request count, five-redirect limit, 2 MiB cap, and total deadline without external network calls.

**Security risks:** Changing host comparison can increase findings for legitimate subdomain flows; this follows the explicit PRD signal definition. Every redirect must still be re-resolved and pinned. Tests must use fixtures/mocks and never contact real suspicious URLs.

### Phase 3 — Accurate consent and feed-refresh copy

**Likely files:** `app/templates/index.html`, `app/static/app.mjs`, `tests/test_app.py`.

**Change:** State the initial read-only GET, up to five public redirect requests, 20-second total budget, and 2 MiB HTML limit alongside the exact selected URL. Change “Refresh selected feeds” to “Refresh both feeds,” because the action requests both providers.

**Focused checks:** Assert the rendered page includes both provider names and the live request limits. Keep the existing backend no-consent test. In the browser, open the dialog for a selected link, verify its normalized URL is displayed, decline, and confirm the local result remains without a scanner call.

**Security risks:** Consent text must describe what the scanner actually does and remain per-link. Feed refresh remains a separate user-confirmed request and must never include the selected URL or message.

### Phase 4 — Regression checks for already-compliant P0 boundaries

**Likely files:** `tests/test_app.py`, `tests/test_feeds.py`, `tests/test_verdict.py`, `tests/test_storage.py`; production files only if a check exposes a real gap.

**Change:** Add fixtures for failed/invalid feed replacement, exact freshness boundaries, exact confidence/verdict values, approved versus unverified reports, and payload/storage privacy. No production change is planned unless these checks disprove the audit.

**Focused checks:** Run focused Python test files and `node --test tests/context.test.mjs`; then run the complete project suites. Use mocked feed fetches, DNS answers, redirects, and HTTP responses only. Inspect keyboard/mobile browser behavior for Phase 1/3.

**Security risks:** A failed or malformed feed must preserve its last valid snapshot and visibly become stale. Confirmed feed/report matches must outrank incomplete scans. Tests must not make live provider/site requests or write raw URL/message data.

## Scope and Review Gates

- Do not add dependencies, run external scans, fetch feeds, deploy, or expose the service publicly.
- Do not create Git metadata or commits.
- Treat all PRD-aligned current behavior as retained; only implement a production change if the focused checks show it is needed.
- The P1 retry feature and deferred public-service features are out of scope.
- **Review gate:** Stop after this audit and plan. Wait for user review before implementation.

