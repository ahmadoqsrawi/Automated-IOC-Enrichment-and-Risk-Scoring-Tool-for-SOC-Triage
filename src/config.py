import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

VT_API_KEY: Optional[str] = os.getenv("VT_API_KEY") or None
ABUSEIPDB_API_KEY: Optional[str] = os.getenv("ABUSEIPDB_API_KEY") or None
URLHAUS_AUTH_KEY: Optional[str] = os.getenv("URLHAUS_AUTH_KEY") or None

OUTPUT_DIR: Path = Path(os.getenv("OUTPUT_DIR", "reports"))
