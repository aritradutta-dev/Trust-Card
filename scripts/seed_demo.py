"""Seed clearly labelled demo threat intelligence data into Trust Card.

Uses ONLY reserved / fake hosts (.test / .example), never real phishing links.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.storage import init_db, replace_feed
from app.urls import canonicalize_url, host_from_url, url_hash

DEMO_URLS = [
    "http://demo-phish.trustcard.test/login",
    "https://demo-threat.trustcard.test/account-update",
    "http://demo-credential-harvest.trustcard.test/verify",
]


def seed_demo(db_path: Path | str | None = None) -> int:
    configured_data_dir = Path(os.environ.get("DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
    target_db = Path(db_path or configured_data_dir / "trust-card.sqlite3")
    init_db(target_db)

    entries = []
    for raw_url in DEMO_URLS:
        canonical = canonicalize_url(raw_url)
        entries.append({
            "url_hash": url_hash(canonical),
            "host": host_from_url(canonical),
        })

    count = replace_feed(
        target_db,
        source="Demo seed",
        entries=entries,
        updated_at=datetime.now(timezone.utc).isoformat(),
    )
    print(f"Seeded {count} demo entries into {target_db} under source 'Demo seed'")
    return count


if __name__ == "__main__":
    seed_demo()

