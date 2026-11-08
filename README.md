# Trust Card

Trust Card is a local-first link checker for people who want a clear, cautious second opinion. Its differentiator is the **context-aware Trust Card**: it checks the selected link alongside a few cues detected from the surrounding message, then explains the evidence and a safer next step. The message itself stays in the browser.

## Run it locally with Docker Compose

1. Copy `.env.example` to `.env`.
2. Set a non-default `ADMIN_USERNAME`, a unique `ADMIN_PASSWORD`, and a different unique `SCANNER_TOKEN`. For example, generate the two secrets with `openssl rand -hex 32`. Keep `.env` private; it is ignored by Git.
3. Optionally add provider keys for PhishTank and URLhaus. The checker works without them, but feed refresh will report that the provider is not configured.
4. Validate the Compose configuration:

   ```sh
   docker compose config --quiet
   ```

   This checks configuration structure and required values; it does not verify secret strength or provider credentials.

5. Start the app:

   ```sh
   docker compose up --build -d
   ```

6. Open [http://127.0.0.1:8000](http://127.0.0.1:8000).

The web app port is bound to `127.0.0.1` by default. SQLite data and downloaded threat feeds stay in the `trust_card_data` Docker volume. Stop the app with `docker compose down`; keep data by leaving the volume in place. `docker compose down -v` deletes the saved local reports and feed data.

For direct local development, install Python 3.10 or later, set `ADMIN_USERNAME` and `ADMIN_PASSWORD`, then run `uv sync --extra test` followed by `uv run uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-access-log`. Without Compose and the scanner service, local checks and admin review work; live scans and feed refresh remain unavailable.

For on-premises use, any network access must be deliberately placed behind the organization's access controls and trusted HTTPS termination. The Compose web port is localhost-only by default; if an operator changes that binding, bind only to an approved private interface or authenticated HTTPS proxy. Keep the scanner unpublished and restrict its outbound network. This repository does not provide a hardened public-service deployment.

## User flow

1. Paste a URL or message. Link extraction and the English-language urgency, credential, payment, and personal-data cues run in the browser.
2. If the message has multiple links, choose one. The browser sends only that URL and the detected cue names to this local app; raw message text is not submitted or stored.
3. Review the local result, which checks cached verified feed indicators and local reports.
4. If you want a live check, review the consent dialog. It shows the submitted URL and explains the initial GET, up to five public redirects, the six-request and 20-second limits, and the 2 MiB HTML read limit. It also states that scripts and forms will not run. Declining leaves the local result intact.
5. Read the Trust Card evidence, feed freshness, coverage, confidence, and suggested next step. “No strong warning found” does not establish that a link is legitimate.

Feed refresh is a separate manual action. The confirmation lists PhishTank and URLhaus before requesting their feeds; the selected URL and message are never sent to either provider. Feed snapshots replace the existing snapshot only after the new file is downloaded and parsed successfully.

## Local report review

Open `/admin/reports` and authenticate using the explicitly configured `ADMIN_USERNAME` and `ADMIN_PASSWORD` values from `.env`. If either is unset, report review is unavailable. Reports are unverified until approved. An approved report affects future checks for the same URL path, with query parameters excluded from its stored fingerprint. A report stores only a SHA-256 indicator fingerprint, hostname, category, state, and timestamps. It does not store the raw URL, message, query string, or scan history.

## Updates, backups, and retained data

Before an update, back up the local database. It contains cached feed indicators and local reports. For a Compose installation, create the backup with SQLite's online backup API, then copy it outside the project directory to a private location:

```sh
docker compose exec -T web python -c 'import sqlite3; source=sqlite3.connect("/app/data/trust-card.sqlite3"); target=sqlite3.connect("/app/data/trust-card-backup.sqlite3"); source.backup(target); target.close(); source.close()'
docker compose cp web:/app/data/trust-card-backup.sqlite3 /path/to/private-backups/trust-card-backup.sqlite3
docker compose exec -T web rm -f /app/data/trust-card-backup.sqlite3
```

Create the destination directory first and replace the example destination with a protected path outside the project. The backup contains reports and cached feed data; protect it like the running installation's data.

To update, install the reviewed release files, then run `docker compose build --pull` and `docker compose up -d`. This rebuilds the local images and keeps the named data volume. Do not use `docker compose down -v` for routine updates.

The named volume retains reports and feed snapshots across stops and updates until you delete the volume. Report rows contain only the approved fields described above; there is no per-report deletion screen. `docker compose down -v` permanently removes the local database, reports, and feed snapshots. Direct development stores its database under `data/` by default, or under `DATA_DIR` when configured. The short-lived in-memory report session contains only the URL fingerprint and hostname, and cannot be used to report after one hour.

## Data and safety boundaries

- The scanner is a separate container. The web app talks to it over an internal Docker network; a second bridge is used only for the localhost-published web port and has IP masquerading disabled. Scanner feed and live-check egress remains on its separate network.
- Live scanning makes read-only HTTP/S GET requests to ports 80/443, validates TLS using the system trust store, reads at most 2 MiB of HTML (non-HTML bodies are skipped), follows at most five redirects, and uses a 20-second scan budget with short DNS and connection timeouts.
- Before every request, DNS answers are checked. Private, loopback, link-local, reserved, and other non-global destinations are blocked. The scanner connects to the validated IP address directly and retains the original host for TLS and HTTP.
- Page JavaScript does not run, forms are not submitted, and downloaded files are not opened. Static inspection checks password forms, redirect destinations, TLS validity/expiry, and a small set of response headers.
- Scanner request paths and web access logs are suppressed so query strings are not written to logs. Feed errors are stored as a generic status and do not overwrite the last valid feed.
- English-only context cues and the conservative hostname comparison can miss attacks or flag legitimate cross-subdomain workflows. This MVP is not a browser reputation service or a guarantee of safety.
- Do not expose this local HTTP deployment to the public internet. A public service needs TLS termination, isolated worker infrastructure, authentication and rate limits, abuse controls, report moderation, operational monitoring, provider-term review, a privacy notice, and explicit opt-in for cross-install sharing; those controls are outside this MVP.

## Provider notes

Configure provider keys in `.env` before requesting a refresh. PhishTank supplies verified phishing data; URLhaus focuses on malware URLs. Review each provider's terms before any commercial public deployment: [PhishTank developer information](https://phishtank.org/developer_info.php) · [URLhaus API](https://urlhaus.abuse.ch/api/).

## Development checks

```sh
node --test tests/context.test.mjs
uv run --extra test python -m unittest discover -s tests -v
docker compose config --quiet
```
