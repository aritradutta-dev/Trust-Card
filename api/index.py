import os

# Ensure Vercel environment flag is present for auto-seeding baseline data
os.environ.setdefault("VERCEL", "1")

from app.main import app
