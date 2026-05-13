import os
import sys
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

VT_API_KEY: Optional[str] = os.getenv("VT_API_KEY") or None
ABUSEIPDB_API_KEY: Optional[str] = os.getenv("ABUSEIPDB_API_KEY") or None
URLHAUS_AUTH_KEY: Optional[str] = os.getenv("URLHAUS_AUTH_KEY") or None

OUTPUT_DIR: Path = Path(os.getenv("OUTPUT_DIR", "reports"))

_REQUIRED = {
    "VT_API_KEY": VT_API_KEY,
    "ABUSEIPDB_API_KEY": ABUSEIPDB_API_KEY,
    "URLHAUS_AUTH_KEY": URLHAUS_AUTH_KEY,
}

missing = [name for name, val in _REQUIRED.items() if not val]
if missing:
    print(f"ERROR: Missing required API keys: {', '.join(missing)}")
    print("Add them to your .env file and try again.")
    sys.exit(1)
