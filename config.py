import os
import secrets

# Persist SECRET_KEY across restarts — generate once and save
_KEY_FILE = os.environ.get("AEGISEDR_SECRET_FILE", "/opt/aegisedr/data/.secret_key")

def _load_or_create_secret() -> str:
    env_key = os.environ.get("AEGISEDR_SECRET")
    if env_key:
        return env_key
    try:
        os.makedirs(os.path.dirname(_KEY_FILE), exist_ok=True)
        if os.path.exists(_KEY_FILE):
            with open(_KEY_FILE) as f:
                key = f.read().strip()
                if len(key) == 64:
                    return key
        key = secrets.token_hex(32)
        with open(_KEY_FILE, "w") as f:
            f.write(key)
        os.chmod(_KEY_FILE, 0o600)
        return key
    except Exception:
        return secrets.token_hex(32)

SECRET_KEY = _load_or_create_secret()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480

DB_PATH = os.environ.get("AEGISEDR_DB", "/opt/aegisedr/data/aegisedr.db")
YARA_RULES_DIR = os.environ.get("AEGISEDR_YARA", "/opt/aegisedr/yara_rules")
QUARANTINE_DIR = os.environ.get("AEGISEDR_QUARANTINE", "/opt/aegisedr/quarantine")
IOC_CACHE_DIR = os.environ.get("AEGISEDR_IOC_CACHE", "/opt/aegisedr/ioc_cache")

APP_HOST = "127.0.0.1"
APP_PORT = 9000

AGENT_HEARTBEAT_TIMEOUT = 300  # seconds before agent marked offline
MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100MB

IOC_FEEDS = [
    {"name": "Abuse.ch URLhaus", "url": "https://urlhaus.abuse.ch/downloads/text/", "type": "url"},
    {"name": "Abuse.ch ThreatFox IPs", "url": "https://threatfox-api.abuse.ch/api/v1/", "type": "threatfox"},
    {"name": "Feodo Tracker", "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "type": "ip"},
    {"name": "CISA Known Exploited", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "cisa"},
]

VIRUSTOTAL_API_KEY = os.environ.get("VT_API_KEY", "")
