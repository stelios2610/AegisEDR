import os
import secrets

# Persist SECRET_KEY across restarts. An ephemeral key would invalidate every
# session on the next boot and hide a broken data directory.
_KEY_FILE = os.environ.get("AEGISEDR_SECRET_FILE", "/opt/aegisedr/data/.secret_key")


def _load_or_create_secret() -> str:
    env_key = os.environ.get("AEGISEDR_SECRET", "").strip()
    if env_key:
        if len(env_key) < 32:
            raise SystemExit("AEGISEDR_SECRET must be at least 32 characters")
        return env_key
    try:
        os.makedirs(os.path.dirname(_KEY_FILE), exist_ok=True)
        if os.path.exists(_KEY_FILE):
            with open(_KEY_FILE) as f:
                key = f.read().strip()
                if len(key) >= 32:
                    return key
        key = secrets.token_hex(32)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(_KEY_FILE, flags, 0o600)
        try:
            os.write(fd, key.encode())
        finally:
            os.close(fd)
        os.chmod(_KEY_FILE, 0o600)
        return key
    except Exception as exc:
        raise SystemExit(
            f"Cannot persist the console secret at {_KEY_FILE}: {exc}. "
            "Set AEGISEDR_SECRET to a stable value of at least 32 characters."
        ) from exc


SECRET_KEY = _load_or_create_secret()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480

DB_PATH = os.environ.get("AEGISEDR_DB", "/opt/aegisedr/data/aegisedr.db")
YARA_RULES_DIR = os.environ.get("AEGISEDR_YARA", "/opt/aegisedr/yara_rules")
QUARANTINE_DIR = os.environ.get("AEGISEDR_QUARANTINE", "/opt/aegisedr/quarantine")
IOC_CACHE_DIR = os.environ.get("AEGISEDR_IOC_CACHE", "/opt/aegisedr/ioc_cache")
TLS_CERT_PATH = os.environ.get("AEGISEDR_TLS_CERT", "/etc/aegisedr/ssl/cert.pem")
SETUP_TOKEN_FILE = os.environ.get(
    "AEGISEDR_SETUP_TOKEN_FILE",
    os.path.join(os.path.dirname(DB_PATH), "setup_token"),
)

APP_HOST = "127.0.0.1"
APP_PORT = 9000

AGENT_HEARTBEAT_TIMEOUT = 300  # seconds before an agent is marked offline
MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100MB
MIN_PASSWORD_LENGTH = 12

IOC_FEEDS = [
    {"name": "Abuse.ch URLhaus", "url": "https://urlhaus.abuse.ch/downloads/text/", "type": "url"},
    {"name": "Abuse.ch ThreatFox IPs", "url": "https://threatfox-api.abuse.ch/api/v1/", "type": "threatfox"},
    {"name": "Feodo Tracker", "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "type": "ip"},
    {"name": "CISA Known Exploited", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "cisa"},
]

VIRUSTOTAL_API_KEY = os.environ.get("VT_API_KEY", "")

ALLOWED_SETTINGS = {
    "auto_quarantine",
    "auto_block_ransomware",
    "virustotal_enabled",
    "ioc_auto_update",
    "ioc_update_interval_hours",
    "agent_heartbeat_interval",
    "retention_days",
    "vt_api_key",
    "threatfox_auth_key",
}
