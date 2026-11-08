# Product Requirements Document: Trust Card

**Status:** Draft for review  
**Version:** 1.0  
**Date:** 2026-11-07  
**Product stage:** Hackathon MVP  
**Primary deployment:** Local or on-premises single installation

## 1. Executive summary

Trust Card helps a person decide what to do when they receive a suspicious web link. The user can paste a link or the message around it. The browser checks the message for a small set of English-language pressure cues and extracts links locally. Trust Card then combines the selected link with cached threat intelligence and, only after clear consent, a bounded live website assessment.

The result is an evidence-based Trust Card: a cautious verdict, what was checked, the signals found, how current the threat data is, and a practical next step. The product never describes a site as “safe.” The original message is not sent to the app or stored.

The MVP is local-first and intended for one personal, team, or on-premises installation. A public, cross-install service is a later phase.

## 2. Problem and opportunity

People encounter suspicious links in email, SMS, chat, social networks, recruitment messages, payment requests, and other everyday communications. A fraudulent page can imitate a bank, school, government service, employer, or online store. A technically valid HTTPS connection does not prove that the site is legitimate.

Existing checks can be difficult to interpret, may focus only on the URL, or may not explain the surrounding request. Users need one accessible flow that combines message context, known threat data, certificate and basic web checks, and clear guidance while limiting what is shared and when.

## 3. Product hypothesis and USP

**USP hypothesis:** Trust Card combines the link with a few locally detected cues from the message, asks before making a live connection, and explains the evidence and next action in plain language.

The intended distinction is the privacy-conscious, consent-first explanation flow. This is a product hypothesis, not a claim that no other product combines similar security signals.

## 4. Target users

### Primary user: anyone checking a suspicious link

Someone receives an unexpected or concerning link and wants a quick, understandable second opinion before opening it or entering information. The user may have limited security knowledge and should not need an account or technical terminology.

### Secondary user: local administrator

The person responsible for a local or on-premises installation reviews community reports. Reports remain unverified until this administrator approves or rejects them.

## 5. Goals

1. Let a user check a URL or a message containing URLs without uploading the raw message.
2. Combine message context, cached threat intelligence, and consent-gated live checks in one flow.
3. Explain findings, source, observation time, confidence, and scan coverage in language a non-specialist can use.
4. Give the user a safer next step without implying that a site is guaranteed safe.
5. Support optional local reporting with administrator review before a report can affect future verdicts.
6. Make the MVP practical to run on a personal computer or an on-premises host.

## 6. Non-goals for the MVP

- Public, multi-tenant scanning or cross-install report sharing.
- Browser extensions, mobile apps, QR/image scanning, or integrations with mail and messaging services.
- Automated or continuous Certificate Transparency monitoring.
- Certificate revocation checking, cipher-suite grading, or claims to detect compromised certificate authorities.
- Malware detonation, page-script execution, form submission, credential testing, or active vulnerability exploitation.
- General-purpose vulnerability scanning, port scanning, or assessment of services beyond HTTP/S on ports 80 and 443.
- Machine-learning verdicts.
- Non-English message analysis.
- Per-link submission to third-party reputation providers.
- A claim that TLS, a clean feed lookup, or a completed scan proves a site is safe.

## 7. MVP scope and product approach

### Selected approach: local-first, single-install checker

The browser handles message parsing. The local app checks cached feeds and local reports. A separate scanner performs bounded live checks only after the user consents for that link. The default deployment binds to localhost; an organization may run the same MVP on-premises behind its own access controls.

This approach keeps message text and report data within the installation and gives the user control over live connections. It does require the operator to configure feed credentials and maintain the local installation.

### Deferred approaches

- **Public hosted service:** Easier for broad access and shared intelligence, but it requires stronger isolation, public-service abuse controls, rate limits, report moderation, and explicit cross-install sharing consent. Defer until those controls and provider terms are resolved.
- **Browser extension first:** Could check links in place, but adds browser-specific distribution and permissions and does not fit the approved paste-and-check MVP. Defer.

## 8. Core user journey

1. The user opens Trust Card without creating an account.
2. The user pastes a URL or a message containing one or more URLs.
3. The browser extracts up to five unique HTTP/S links and displays detected message cues. Raw message text remains in the browser.
4. If there are multiple links, the user chooses one. If there are none, the product explains what input is needed.
5. Trust Card runs a local check against cached threat feeds and local administrator-approved reports. This step does not connect to the selected site.
6. The user sees the local result and its coverage. They may stop here or request a live check.
7. Before a live check, the user sees the exact selected link and a single consent dialog listing all planned requests and limits. Declining preserves the local result and makes no live scan request.
8. Trust Card presents a verdict, evidence, sources and times, confidence, coverage, feed freshness, and a safer next step.
9. The user may optionally report the link. The report is unverified until reviewed by the local administrator.

Feed refresh is a separate, manual action. Before it runs, Trust Card lists the feed providers it will contact. It never sends the checked URL or message text to those providers.

## 9. Functional requirements

Priority definitions: **P0** is required for the MVP; **P1** is useful if time permits; **Later** is out of MVP scope.

| ID | Priority | Requirement | Acceptance criteria |
|---|---|---|---|
| FR-01 | P0 | Accept a URL or message in a paste field. | Supports up to 12,000 characters; includes a clear action and helpful empty/error states; no account is required to scan. |
| FR-02 | P0 | Extract links in the browser. | Extracts up to five unique HTTP/S URLs; ignores malformed URLs and credential-bearing URLs; displays a choice when multiple links are found. Normalize the hostname to lowercase ASCII/IDNA, remove a trailing dot and fragment, and remove the default port; preserve the path and query for exact feed lookup. |
| FR-03 | P0 | Detect message-context cues in the browser. | Detects English-language urgency, credential, payment, and personal-data cues; sends only the selected URL and cue category flags to the local app. |
| FR-04 | P0 | Run a local-only check. | Looks up the selected URL against cached threat data and local reports; makes no connection to the selected website; clearly labels local-only coverage. |
| FR-05 | P0 | Gate live checks on explicit consent. | The dialog identifies the submitted URL and explains that it may make one request to that URL plus up to five requests to public redirect destinations; approval is per link; decline results in no live scan request. No alternate scheme, `www`, or guessed URL variants are probed. |
| FR-06 | P0 | Perform bounded live website checks. | Makes read-only GET requests using the submitted scheme on ports 80/443; follows no more than five public redirects; reads at most 2 MiB of HTML; completes or times out within 20 seconds. |
| FR-07 | P0 | Assess certificate and basic web signals. | Validates TLS hostname and chain against the system trust store; reports expired/untrusted/mismatched certificates and certificates expiring within 14 days; examines a small set of security headers, redirect destinations, and static form destinations; does not run scripts or submit forms. |
| FR-08 | P0 | Protect the scanner from server-side request forgery. | Blocks private, loopback, link-local, reserved, and metadata destinations; validates and pins addresses before connecting; repeats address checks after redirects and DNS changes. |
| FR-09 | P0 | Use cautious, explainable verdicts. | Supports `Known threat`, `Suspicious`, `No strong warning found`, and `Unable to check`; a technical TLS or header issue alone does not prove phishing; never labels a site “safe.” |
| FR-10 | P0 | Show an evidence-based Trust Card. | Displays verdict, confidence, scan coverage, checked time, findings, source and observation time where available, redirect hosts where applicable, threat-feed freshness, and next steps. |
| FR-11 | P0 | Refresh threat feeds manually. | Supports PhishTank verified-phishing data and URLhaus malware URL data; before refresh, names both providers; requires operator-configured provider credentials; does not send the checked URL; keeps the last valid feed if download or parsing fails; exposes missing or stale feed status. A feed is stale after 24 hours or a refresh error. Feed lookup uses an exact hash of the normalized URL including query; reports use a fingerprint without query or fragment. |
| FR-12 | P0 | Accept optional user reports. | Accepts phishing, malware, impersonation, or other as categories; stores an indicator fingerprint, hostname, category, state, and timestamps; excludes raw message, URL query, and full scan history; new reports are unverified. |
| FR-13 | P0 | Review local reports. | Requires local administrator authentication; supports approve and reject; only approved reports can affect future verdicts. |
| FR-14 | P0 | Provide responsive, accessible screens. | Core flow works on mobile and desktop; keyboard focus is visible; labels and errors are programmatically associated; color is not the only status cue; reduced-motion preferences are respected. |
| FR-15 | P1 | Let users retry a failed or partial scan. | Retry follows the same consent requirement and does not erase the prior result until a new result is available. |

## 10. Verdict and evidence rules

- **Known threat:** An exact URL-hash match from a verified threat feed or a matching administrator-approved local report fingerprint (scheme, host, and path; query and fragment excluded).
- **Suspicious:** One high-signal finding or at least two independent medium-signal groups. Message context contributes evidence but does not determine the verdict by itself.
- **No strong warning found:** The available checks completed and did not meet a stronger verdict rule. This is not a guarantee of safety.
- **Unable to check:** The checks could not complete sufficiently to support a useful result, unless a confirmed threat match is already available.

Each finding should be explainable with a category, severity, plain-language explanation, source, and observation time when available. Coverage and data freshness must remain visible so a no-match result is not mistaken for a complete assurance.

### MVP signal mapping

- **High signal — credential form:** A statically detected password form posts to a different hostname or a non-HTTP/S destination.
- **High signal — restricted redirect destination:** The scanner blocks a redirect to a private or restricted network address. This safety block contributes to a suspicious result; the scanner must not connect to that address.
- **Medium signal — redirect:** A redirect goes to a different hostname, exceeds the inspection limit, or uses an invalid or unsupported destination.
- **Medium signal — message context:** A credential, payment, or personal-data request cue. These share one `message_context` group; multiple cues in that group count as one independent group. Urgency is low severity and does not count toward the suspicious threshold by itself.
- **Technical-only findings:** TLS validation, certificate expiry, headers, response readability, and other technical coverage findings do not independently produce `Suspicious`.

`Suspicious` requires at least one high signal or medium signals from two independent groups. Findings from the same group are not independent. A confirmed feed match or approved local report takes precedence as `Known threat`.

Confidence reflects evidence strength and feed freshness: confirmed matches are high; `Unable to check` is low; suspicious results are high with fresh feeds and moderate with stale or missing feeds; no-strong-warning results are moderate with fresh feeds and limited with stale or missing feeds. Coverage is `local-only` when the site was not contacted, `full` when the live page checks and local feeds are current, and `partial` when a live check or the local feed data is incomplete.

## 11. Privacy and data handling requirements

| Data | Handling |
|---|---|
| Raw message text | Processed only in the browser; never sent to the API, scanner, or feeds; never stored. |
| Selected URL | Sent to the local app for local lookup; sent to the separate scanner only after live-scan consent; query strings are excluded from logs and report storage. |
| Context flags | Only the supported cue category names are sent with the selected URL; message text and quoted fragments are not sent. |
| User report | Stores indicator fingerprint, hostname, category, review state, and timestamps; remains unverified pending admin review. |
| Threat feeds | Stored locally with source and update status; refresh is manual and user-confirmed. |
| Scan output | Used to form the current result; raw message and full scan history are not retained. |

Feed snapshots and local report records persist with the installation's data store. Removing that local data clears them. The MVP has no automatic report expiry or full scan-history view.

The product must not add analytics or telemetry that captures URLs, messages, or user behavior by default. Any future cross-install sharing requires a separate opt-in and a public-service privacy review.

## 12. UX and visual design requirements

The supplied Google Stitch export is a **visual reference only**. It may guide color, spacing, typography, card shape, responsive composition, and visual hierarchy. It does not define product behavior, data claims, metrics, security guarantees, or features.

The product UI should:

- Use a calm, accessible visual style with light lavender/neutral surfaces, blue primary actions, restrained status colors, and clear text hierarchy.
- Make the paste-and-check action the main entry point.
- Show detected link count and context cues before a scan, and make multi-link selection unambiguous.
- Present the result as a readable Trust Card with evidence and next steps, not as a single unexplained score.
- Make consent, coverage limits, feed age, and uncertainty easy to find.
- Use local/system fonts and assets so the local installation does not depend on third-party UI CDNs.
- Exclude mockup-only analytics, unsupported threat claims, and unverified data from the finished product.

## 13. Non-functional requirements

### Security

- Run live scanning in a separate, restricted service.
- Keep the web app bound to `127.0.0.1` by default.
- Restrict outbound scan destinations and request behavior as described in FR-06 through FR-08.
- Redact URL query strings from logs and do not persist full scan history.
- Require a configured local admin credential for report review; do not expose unauthenticated report actions.

### Performance

- Local checks should return promptly; proposed target is under 2 seconds at the 95th percentile on a typical local installation.
- A live scan must obey the 20-second total budget.
- The interface should remain usable while a scan or feed refresh is in progress and communicate its state.

### Availability and feed quality

- A failed feed refresh must not replace a last valid snapshot.
- Feed age or missing status must be visible in both the feed area and relevant Trust Card coverage.
- A failed scanner must produce a clear limited-coverage or unable-to-check state.

### Accessibility and compatibility

- Target WCAG 2.1 AA for core flow contrast, keyboard operation, focus, form labels, and status announcements.
- Support current desktop and mobile browsers with JavaScript enabled; the UI must explain that browser-side parsing requires JavaScript.
- English-only cue detection is an explicit MVP limit.

## 14. Success measures

No usage analytics are enabled by default. Evaluate the MVP using local pilot sessions and release checks:

1. At least 80% of pilot users can identify the verdict and choose the recommended next step after a single-use scenario test. **Proposed target.**
2. Local-only checks complete in under 2 seconds at the 95th percentile on the pilot installation. **Proposed target.**
3. Every acceptance scenario in Section 15 passes before release.
4. Verification confirms that the raw message does not appear in any API request, database record, or application log.
5. Users can decline live scanning and still understand the limited local result.

The pilot should collect only consented usability observations and aggregate timings; do not retain scanned URLs or messages for product analytics.

## 15. MVP acceptance scenarios

1. **Known phishing or malware match:** Show `Known threat`, the matching source, observation/update time, and a clear instruction not to open or enter information.
2. **Suspicious first-seen link:** When independent high-signal evidence meets the verdict rule, show `Suspicious` and identify the evidence that contributed.
3. **No strong finding:** A completed check with no strong signal says `No strong warning found`, with coverage and uncertainty visible.
4. **Declined consent:** The local result remains visible; no live scanner request is made.
5. **Unsafe destination:** A private or internal address is blocked before a connection, including when reached via redirect or DNS change.
6. **Stale or unavailable feeds:** The state remains visible; a feed-only no-match is not presented as a clean bill of health.
7. **Report workflow:** A new report remains unverified and does not change future verdicts until admin approval.
8. **Feed refresh failure:** The previous valid feed remains available and the failure is visible to the user.
9. **Multiple links:** The user can select exactly one of up to five extracted links before analysis.
10. **Mobile use:** The user can complete paste, selection, consent, result review, and reporting without horizontal scrolling or color-only status interpretation.

## 16. Deployment and rollout

### MVP release

- Package the local/on-prem installation with Docker Compose.
- Bind the app to localhost by default and document the extra controls needed for on-prem access.
- Assume the operator restricts access to an on-prem instance; scan/report submission does not require per-user accounts in v1, while report review requires the configured local administrator credential.
- Require explicit configuration for the admin credential and scanner service token.
- Document optional feed-provider credentials and terms.
- Publish setup, update, backup, and local data-retention guidance.

### Later public-service phase

Before a public launch, add isolated worker infrastructure, queueing, authentication and rate limits, abuse controls, report moderation, operational monitoring, HTTPS deployment, provider-term review, privacy notice, and explicit cross-install sharing consent. Public deployment is not an MVP acceptance criterion.

## 17. Risks and mitigations

| Risk | Mitigation |
|---|---|
| False negatives or fast-changing malicious pages | Show coverage and feed freshness; use cautious language; recommend direct navigation to official sites. |
| False positives from context cues or technical weaknesses | Explain each finding; do not let context or TLS/header issues alone assert phishing; keep deterministic rules visible. |
| SSRF or DNS rebinding through user-supplied links | Isolate the scanner; block non-public IP ranges; pin checked destinations; repeat checks at every redirect. |
| Users mistake HTTPS or “no warning” for safety | Explicitly state that HTTPS and a clean result are not proof of legitimacy. |
| Feed licensing or provider availability changes | Keep refresh manual, retain prior valid feeds, display status, and review provider terms before commercial/public deployment. |
| Malicious or mistaken community reports | Keep reports unverified until local admin review; only approved reports affect verdicts. |
| Public exposure of a local deployment | Bind to localhost by default; document that public exposure requires a separate hardened deployment phase. |

## 18. Assumptions and open decisions

### Confirmed product decisions

- The first audience is anyone checking a suspicious link.
- The product is a context-aware web checker.
- Local/on-premises use comes before a public service.
- The workflow is hybrid: ask before each user-requested remote action.
- A live scan uses one consent per link and lists all planned requests and limits.
- The original message is never sent or stored.
- Feed refresh is manual and separately confirmed.
- MVP supports English cues and does not use machine-learning verdicts.

### Assumptions to validate during the pilot

- Users understand the difference between a local-only check and a live scan when coverage is labeled in plain language.
- Users prefer an evidence explanation and next step over a numeric risk score.
- A single-instance local report queue is sufficient for the hackathon MVP.
- A 12,000-character input and a maximum of five links cover common paste cases.

### Open decisions before a public release

- Provider terms and credentials for public/commercial feed use.
- Hosting, jurisdiction, retention, and privacy obligations for any public service.
- Moderation policy and appeal process for cross-install reports.
- Whether to add language support, browser integrations, or enrolled-domain certificate monitoring.

## 19. Product boundaries

Trust Card is a cautious aid for deciding how to handle a link. It is not an antivirus product, a comprehensive vulnerability scanner, a certificate authority monitor, or a guarantee against fraud. The MVP improves the user’s ability to inspect evidence and act carefully; it cannot prove that an unflagged website is legitimate.
