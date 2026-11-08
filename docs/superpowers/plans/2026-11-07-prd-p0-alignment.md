# Trust Card P0 Alignment Implementation Plan

> **Superseded.** The current user instruction is audit and plan only. Use `2026-11-07-trust-card-mvp.md`; do not execute this earlier plan.

> **For agentic workers:** Implement task-by-task in this session. Each phase ends with its focused checks. No Git metadata or commits.

**Goal:** Close the remaining P0 gaps in the existing local-first Trust Card MVP without replacing its architecture.

**Architecture:** Keep browser-side parsing, the FastAPI local app, SQLite feed/report storage, and the isolated scanner. Use the browser’s built-in URL parser for canonical links, compare hostnames exactly for static form and redirect signals, and clarify existing consent text.

**Tech Stack:** Python 3.10+, FastAPI, SQLite, vanilla JavaScript modules, Node’s built-in test runner, Python `unittest`.

**Spec:** `docs/PRD.md` (FR-01 through FR-14 and Sections 10–16).

## Global Constraints

- Accept up to 12,000 characters and extract up to five unique HTTP/S links.
- Normalize the hostname to lowercase ASCII/IDNA, remove a trailing dot and fragment, remove the default port, and preserve path and query for exact feed lookup.
- Process raw message text only in the browser; send only the selected URL and supported cue flags to the local app.
- Ask for per-link consent before one initial read-only GET and up to five public redirect requests; inspect no guessed URL variants.
- Keep the scanner to ports 80/443, a 2 MiB HTML limit, five redirects, and a 20-second total budget.
- Keep the app bound to localhost by default; do not add telemetry or full scan history.
- Preserve existing feed, report, verdict, and SSRF safeguards; do not use live suspicious URLs or feed providers in checks.

## Review Focus

- URLs with credentials, malformed syntax, fragments, trailing-dot hosts, default ports, IDNs, IPv6 literals, and equivalent spellings: browser extraction rejects or normalizes them consistently (`context.test.mjs`).
- Multiple links: no URL is analyzed until the user selects one (`app.mjs`; verify in the browser preview).
- Redirects and form actions on sibling hostnames: exact hostname differences produce the PRD’s medium/high signals (`test_scanner.py`).
- Redirects to private destinations or mixed public/private DNS answers: the scanner blocks before connecting (`test_scanner.py`).
- Consent disclosure and decline behavior: show the submitted URL and request budget; declining never calls the scanner (`test_app.py` and browser preview).

## Audit: PRD to Current Code

| P0 area | Current implementation | Gap / phase |
|---|---|---|
| FR-01 input | 12,000-character paste field, empty/error states, no account | Aligned |
| FR-02 link extraction | Browser extracts up to five HTTP/S links and skips credential URLs; server normalizes for lookup | Browser submits raw spelling, keeps fragments, and may treat fragment variants as distinct; Phase 1 |
| FR-03 context | Browser detects all four cue categories; API schema accepts only flags, not raw message | Aligned |
| FR-04 local check | Cached exact feed lookup and local report lookup; no site connection | Aligned |
| FR-05 consent | Per-link dialog and API consent gate exist; selected URL is displayed | Dialog does not state one initial request explicitly; Phase 3 |
| FR-06–08 scanner | Separate scanner, GET, limits, TLS validation, DNS pinning, redirect revalidation, private-address blocking | Core behavior aligned; hostname comparison misses sibling-host changes; Phase 2 |
| FR-09–10 verdict and Trust Card | PRD signal groups, cautious verdicts, confidence, freshness, coverage, timestamps, evidence, next steps | Aligned |
| FR-11 feed refresh | Named providers, manual confirmation, exact query-inclusive hashes, status/failure visibility, last valid snapshot retained | Aligned |
| FR-12–13 reports | Query-free fingerprint, unverified by default, local authenticated review | Aligned |
| FR-14 accessible screens | Responsive layout, labels, live status, visible focus, reduced-motion handling | Multiple-link picker preselects the first URL; Phase 1 |

## Approaches

1. **Use native `URL` normalization and keep existing modules (selected):** smallest change; handles IDNA, hostname case, and default ports without a dependency. Remove a trailing hostname dot, strip the fragment before using `href`, and deduplicate that normalized value.
2. **Add a URL-normalization package:** more explicit library behavior but unnecessary in the browser and adds a dependency.
3. **Keep the conservative suffix comparison:** avoids some cross-subdomain findings but conflicts with the PRD’s “different hostname” rule; use exact hostname comparison instead.

## Files and Responsibilities

- `app/static/context.mjs`: browser-only URL extraction, normalization, deduplication, and cue detection.
- `app/static/app.mjs`: selected-link state, local/live flow, consent and feed-refresh labels.
- `app/templates/index.html`: accessible selection and exact request-scope disclosure.
- `scanner/engine.py`: exact-host comparison for redirect and credential-form evidence.
- `tests/context.test.mjs`, `tests/test_scanner.py`, `tests/test_app.py`: focused checks for changed behavior.

## Phase 1: Normalize Links and Require a Choice

**Files:** `app/static/context.mjs`, `app/static/app.mjs`, `tests/context.test.mjs`.

- [ ] Add a failing browser extraction check covering IDNA/lowercase hostname, trailing-dot removal, default port, fragment removal, preserved path/query, IPv6 literals, and deduplication across fragment variants.
- [ ] Run `node --test tests/context.test.mjs` and confirm the new assertion fails on current output.
- [ ] Normalize with the built-in `URL` parser: clear `.hash`, remove a final dot from `.hostname`, retain valid IPv6 brackets, then use `.href`; return normalized values and deduplicate by that value.
- [ ] Remove the default checked state from the first radio. Keep the existing checked-radio guard so clicking “Check selected link locally” without a choice does not submit a URL.
- [ ] Run the focused Node test and verify in the browser that no multiple-link choice is preselected and no local request is sent until a choice is made.

## Phase 2: Match the PRD’s Hostname Signals

**Files:** `scanner/engine.py`, `tests/test_scanner.py`.

- [ ] Add failing checks for a password form posting to a sibling hostname and a redirect to a sibling hostname; assert the existing low-risk same-host form case remains unflagged.
- [ ] Run the focused scanner tests and confirm the sibling-host checks fail for the current suffix comparison.
- [ ] Replace `_same_site` with a small exact-hostname comparison and use it for redirects and static credential form destinations.
- [ ] Add a mocked redirect-to-loopback check that proves no second request is made; all HTTP/DNS behavior in these tests remains mocked.
- [ ] Run `python -m unittest discover -s tests -p 'test_scanner.py' -v`.

## Phase 3: State the Live Request Budget

**Files:** `app/templates/index.html`, `app/static/app.mjs`, `tests/test_app.py`.

- [ ] Add a failing home-page assertion requiring disclosure of one initial read-only GET and up to five public redirect GETs.
- [ ] Run `python -m unittest discover -s tests -p 'test_app.py' -v` and confirm the disclosure check fails.
- [ ] Update the live-consent dialog to state that request budget and change the feed action label from “selected feeds” to “both feeds” because the action requests both named providers.
- [ ] Run the focused app test; retain the existing no-consent scanner-call assertion and visually confirm that the exact normalized selected URL is shown in the dialog.

## Final Verification

- [ ] Run `node --test tests/context.test.mjs`.
- [ ] Run the complete Python suite with `python -m unittest discover -s tests -v`.
- [ ] Run `node --check app/static/app.mjs`.
- [ ] Inspect `git status` only if Git metadata already exists; do not initialize a repository or create commits.

