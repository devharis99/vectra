import os
from pathlib import Path

# Base storage directories (supports VECTRA_DATA_DIR with fallback to legacy CVESEARCH_DATA_DIR)
DEFAULT_DATA_DIR = Path(
    os.environ.get("VECTRA_DATA_DIR", os.environ.get("CVESEARCH_DATA_DIR", Path.home() / ".local" / "share" / "vectra"))
)
DEFAULT_DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DEFAULT_DATA_DIR / "cves.db"
# If not present in ~/.local/share/vectra/cves.db, check legacy path ~/.local/share/vectra/cves.db
if not DB_PATH.exists():
    legacy_path = Path.home() / ".local" / "share" / "vectra" / "cves.db"
    if legacy_path.exists():
        DB_PATH = legacy_path

# CVE dataset URLs
CVEPROJECT_RELEASE_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"

# GTFOBins dataset URLs
GTFOBINS_REPO_ZIP = "https://github.com/GTFOBins/GTFOBins.github.io/archive/refs/heads/master.zip"

# Batch insert sizing for SQLite
DB_BATCH_SIZE = 5000
