import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY: str = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
URLHAUS_AUTH_KEY: str = os.getenv("URLHAUS_AUTH_KEY", "")

OUTPUT_DIR: str = "reports"
