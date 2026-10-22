"""Configuration: .env-style file + process environment -> Settings."""
from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from pathlib import Path

SEVERITIES = ["info", "low", "medium", "high", "critical"]
AUTONOMY_LEVELS = ["observe", "contain", "full"]

# provider -> (adapter, default base url, default model)
PROVIDER_PRESETS: dict[str, tuple[str, str | None, str | None]] = {
    "deepseek": ("openai", "https://api.deepseek.com", "deepseek-chat"),
    "openai": ("openai", "https://api.openai.com/v1", None),
    "anthropic": ("anthropic", "https://api.anthropic.com", "claude-sonnet-5-5"),
    "openrouter": ("openai", "https://openrouter.ai/api/v1", None),
    "groq": ("openai", "https://api.groq.com/openai/v1", None),
    "mistral": ("openai", "https://api.mistral.ai/v1", None),
    "gemini": ("openai", "https://generativelanguage.googleapis.com/v1beta/openai", None),
    "ollama": ("openai", "http://localhost:11434/v1", None),
    "custom": ("openai", None, None),
}


def severity_rank(sev: str) -> int:
    try:
        return SEVERITIES.index((sev or "info").lower())
    except ValueError:
        return 0


def parse_env_file(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, sep, val = line.partition("=")
        if not sep:
            continue
        key, val = key.strip(), val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        else:
            cut = val.find(" #")
            if cut != -1:
                val = val[:cut].rstrip()
        out[key] = val
    return out


def find_env_file() -> Path | None:
    candidates = [os.environ.get("WARDEN_ENV_FILE"), "/etc/warden/warden.env", ".env"]
    for c in candidates:
        if c and Path(c).is_file():
            return Path(c)
    return None


@dataclass
class LLMConfig:
    provider: str
    adapter: str
    base_url: str
    model: str
    api_key: str
    temperature: float = 0.2
    max_tokens: int = 4096
    timeout: int = 180


@dataclass
class Settings:
    env: dict[str, str]
    env_file: Path | None
    llm: LLMConfig | None
    llm_fallback: LLMConfig | None
    llm_error: str | None
    hostname: str
    state_dir: Path
    autonomy: str
    max_steps: int
    max_tokens_per_run: int
    daily_token_budget: int
    allow_reboot: bool
    harden_sysctl: bool
    incident_max_checks: int
    allowlist: list[str]
    trusted_login_days: int
    sentinel_enabled: bool
    sentinel_interval: int
    ban_base_minutes: int
    ban_max_minutes: int
    ssh_max_failures: int
    ssh_window: int
    conn_per_ip_max: int
    http_max_req_per_min: int
    http_max_4xx_per_min: int
    http_exploit_hits: int
    http_auth_fail_max: int
    attack_wave_bans: int
    web_ban_private: bool
    trusted_proxies: list[str]
    cloudflare_api_token: str
    cloudflare_account_id: str
    cloudflare_zone_id: str
    retention_days: int
    backup_max_mb: int
    web_access_logs: list[str]
    nft_syn_rate: int
    nft_conn_limit: int
    nft_icmp_rate: int
    email_to: list[str]
    email_from: str
    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_password: str
    email_min_severity: str
    email_max_per_hour: int
    email_on_start: bool
    extra: dict = field(default_factory=dict)

    @property
    def db_path(self) -> Path:
        return self.state_dir / "warden.db"

    @property
    def pid_path(self) -> Path:
        return self.state_dir / "warden.pid"

    @property
    def backup_dir(self) -> Path:
        return self.state_dir / "backups"

    @property
    def email_configured(self) -> bool:
        return bool(self.email_to and self.smtp_host)

    def autonomy_at_least(self, level: str) -> bool:
        return AUTONOMY_LEVELS.index(self.autonomy) >= AUTONOMY_LEVELS.index(level)


class _Env:
    def __init__(self, data: dict[str, str]):
        self.data = data

    def str(self, key: str, default: str = "") -> str:
        v = self.data.get(key)
        return default if v is None or v == "" else v

    def int(self, key: str, default: int) -> int:
        try:
            return int(self.str(key, str(default)))
        except ValueError:
            return default

    def float(self, key: str, default: float) -> float:
        try:
            return float(self.str(key, str(default)))
        except ValueError:
            return default

    def bool(self, key: str, default: bool) -> bool:
        v = self.data.get(key)
        if v is None or v == "":
            return default
        return v.strip().lower() in ("1", "true", "yes", "on")

    def list(self, key: str, default: str = "") -> list[str]:
        raw = self.str(key, default)
        return [p for p in raw.replace(",", " ").split() if p]


def _llm_config(env: _Env, prefix: str) -> LLMConfig | None:
    """prefix is 'LLM_' or 'LLM_FALLBACK_'. Raises ValueError on misconfiguration."""
    provider = env.str(prefix + "PROVIDER", "deepseek" if prefix == "LLM_" else "").lower()
    if not provider:
        return None
    if provider not in PROVIDER_PRESETS:
        raise ValueError(f"{prefix}PROVIDER={provider!r} unknown; choose one of {sorted(PROVIDER_PRESETS)}")
    adapter, base, model = PROVIDER_PRESETS[provider]
    base_url = env.str(prefix + "BASE_URL", base or "")
    model = env.str(prefix + "MODEL", model or "")
    key = env.str(prefix + "API_KEY", env.str(f"{provider.upper()}_API_KEY", ""))
    if not base_url:
        raise ValueError(f"{prefix}BASE_URL is required for provider {provider!r}")
    if not model:
        raise ValueError(f"{prefix}MODEL is required for provider {provider!r}")
    if not key and provider not in ("ollama", "custom"):
        raise ValueError(f"no API key: set {prefix}API_KEY or {provider.upper()}_API_KEY")
    return LLMConfig(
        provider=provider,
        adapter=adapter,
        base_url=base_url.rstrip("/"),
        model=model,
        api_key=key,
        temperature=env.float("LLM_TEMPERATURE", 0.2),
        max_tokens=env.int("LLM_MAX_TOKENS", 4096),
        timeout=env.int("LLM_TIMEOUT", 180),
    )


def load_settings(env_file: Path | None = None, overrides: dict[str, str] | None = None) -> Settings:
    env_file = env_file or find_env_file()
    data: dict[str, str] = {}
    if env_file and env_file.is_file():
        data.update(parse_env_file(env_file.read_text(encoding="utf-8-sig")))
    # real environment wins over the file
    data.update({k: v for k, v in os.environ.items() if k.startswith(("LLM_", "WARDEN_", "SMTP_", "EMAIL_", "CLOUDFLARE_")) or k.endswith("_API_KEY")})
    if overrides:
        data.update(overrides)
    e = _Env(data)

    llm = fallback = None
    llm_error = None
    try:
        llm = _llm_config(e, "LLM_")
        fallback = _llm_config(e, "LLM_FALLBACK_")
    except ValueError as exc:
        llm_error = str(exc)

    autonomy = e.str("WARDEN_AUTONOMY", "full").lower()
    if autonomy not in AUTONOMY_LEVELS:
        autonomy = "observe"
    min_sev = e.str("EMAIL_MIN_SEVERITY", "medium").lower()
    if min_sev not in SEVERITIES:
        min_sev = "medium"

    return Settings(
        env=data,
        env_file=env_file,
        llm=llm,
        llm_fallback=fallback,
        llm_error=llm_error,
        hostname=e.str("WARDEN_HOSTNAME", socket.gethostname()),
        state_dir=Path(e.str("WARDEN_STATE_DIR", "/var/lib/warden")),
        autonomy=autonomy,
        max_steps=max(5, e.int("AGENT_MAX_STEPS", 30)),
        max_tokens_per_run=max(20000, e.int("AGENT_MAX_TOKENS_PER_RUN", 250000)),
        daily_token_budget=max(0, e.int("WARDEN_DAILY_TOKEN_BUDGET", 2000000)),
        allow_reboot=e.bool("WARDEN_ALLOW_REBOOT", False),
        harden_sysctl=e.bool("WARDEN_HARDEN_SYSCTL", True),
        incident_max_checks=e.int("INCIDENT_MAX_CHECKS", 12),
        allowlist=e.list("WARDEN_ALLOWLIST"),
        trusted_login_days=e.int("TRUSTED_LOGIN_DAYS", 14),
        sentinel_enabled=e.bool("SENTINEL_ENABLED", True),
        sentinel_interval=max(5, e.int("SENTINEL_INTERVAL", 10)),
        ban_base_minutes=e.int("BAN_BASE_MINUTES", 60),
        ban_max_minutes=e.int("BAN_MAX_MINUTES", 43200),
        ssh_max_failures=e.int("SSH_MAX_FAILURES", 8),
        ssh_window=e.int("SSH_WINDOW_SECONDS", 600),
        conn_per_ip_max=e.int("CONN_PER_IP_MAX", 150),
        http_max_req_per_min=e.int("HTTP_MAX_REQ_PER_MIN", 600),
        http_max_4xx_per_min=e.int("HTTP_MAX_4XX_PER_MIN", 120),
        http_exploit_hits=e.int("HTTP_EXPLOIT_HITS", 3),
        http_auth_fail_max=e.int("HTTP_AUTH_FAIL_MAX", 20),
        attack_wave_bans=e.int("ATTACK_WAVE_BANS", 20),
        web_ban_private=e.bool("WEB_BAN_PRIVATE", False),
        trusted_proxies=e.list("TRUSTED_PROXIES", "cloudflare"),
        cloudflare_api_token=e.str("CLOUDFLARE_API_TOKEN"),
        cloudflare_account_id=e.str("CLOUDFLARE_ACCOUNT_ID"),
        cloudflare_zone_id=e.str("CLOUDFLARE_ZONE_ID"),
        retention_days=max(7, e.int("WARDEN_RETENTION_DAYS", 90)),
        backup_max_mb=max(10, e.int("WARDEN_BACKUP_MAX_MB", 200)),
        web_access_logs=e.list(
            "WEB_ACCESS_LOGS",
            "/var/log/nginx/access.log /var/log/apache2/access.log /var/log/caddy/access.log",
        ),
        nft_syn_rate=e.int("NFT_SYN_RATE_PER_SEC", 100),
        nft_conn_limit=e.int("NFT_CONN_LIMIT", 500),
        nft_icmp_rate=e.int("NFT_ICMP_RATE_PER_SEC", 20),
        email_to=e.list("EMAIL_TO"),
        email_from=e.str("EMAIL_FROM", f"warden@{socket.gethostname()}"),
        smtp_host=e.str("SMTP_HOST"),
        smtp_port=e.int("SMTP_PORT", 587),
        smtp_user=e.str("SMTP_USER"),
        smtp_password=e.str("SMTP_PASSWORD"),
        email_min_severity=min_sev,
        email_max_per_hour=e.int("EMAIL_MAX_PER_HOUR", 6),
        email_on_start=e.bool("EMAIL_ON_START", True),
    )


# Settings the agent may tune at runtime (stored in kv as overrides): name -> (min, max)
TUNABLE: dict[str, tuple[int, int]] = {
    "ssh_max_failures": (3, 50),
    "ssh_window": (60, 7200),
    "conn_per_ip_max": (20, 5000),
    "http_max_req_per_min": (60, 100000),
    "http_max_4xx_per_min": (20, 10000),
    "http_exploit_hits": (1, 50),
    "ban_base_minutes": (5, 1440),
    "ban_max_minutes": (60, 525600),
    "sentinel_interval": (5, 300),
    "http_auth_fail_max": (3, 1000),
    "attack_wave_bans": (5, 1000),
    "nft_syn_rate": (10, 100000),
    "nft_conn_limit": (20, 100000),
}
NFT_TUNABLES = {"nft_syn_rate", "nft_conn_limit"}


def apply_overrides(settings: Settings, overrides: dict[str, str]) -> None:
    for k, v in overrides.items():
        if k in TUNABLE:
            lo, hi = TUNABLE[k]
            try:
                setattr(settings, k, max(lo, min(hi, int(v))))
            except ValueError:
                pass
