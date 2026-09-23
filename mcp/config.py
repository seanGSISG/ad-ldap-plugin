"""Environment-derived connection configuration for the AD LDAP MCP server.

All connection settings come from ``AD_*`` environment variables (injected by the
plugin's ``.mcp.json`` ``env`` block). Credentials live only in the environment
and are never logged or rendered in ``repr``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Mapping

# Variables read from the environment.
ENV_SERVER = "AD_SERVER"
ENV_PORT = "AD_PORT"
ENV_BASE_DN = "AD_BASE_DN"
ENV_BIND_USER = "AD_BIND_USER"
ENV_BIND_PASSWORD = "AD_BIND_PASSWORD"
ENV_USE_SSL = "AD_USE_SSL"
ENV_CA_CERTS = "AD_CA_CERTS"
ENV_TLS_VALIDATE = "AD_TLS_VALIDATE"
ENV_PAGE_SIZE = "AD_PAGE_SIZE"
ENV_USER_SEARCH_BASE = "AD_USER_SEARCH_BASE"
ENV_COMPUTER_SEARCH_BASE = "AD_COMPUTER_SEARCH_BASE"

_REQUIRED = (ENV_SERVER, ENV_BASE_DN, ENV_BIND_USER, ENV_BIND_PASSWORD)

_TRUTHY = {"1", "true", "yes", "on"}
_FALSEY = {"0", "false", "no", "off"}


class ADConfigError(ValueError):
    """Raised when required configuration is missing or malformed."""


def _parse_bool(raw: str | None, *, default: bool, name: str) -> bool:
    if raw is None or raw.strip() == "":
        return default
    value = raw.strip().lower()
    if value in _TRUTHY:
        return True
    if value in _FALSEY:
        return False
    raise ADConfigError(f"{name} must be a boolean (got {raw!r})")


def _parse_optional_str(raw: str | None, *, name: str) -> str | None:
    """Return a stripped non-empty string, or None when unset/blank.

    A variable that is *present but blank/whitespace* is rejected: setting an
    empty scoped search base is almost certainly a mistake, so fail loudly rather
    than silently falling back to base_dn.
    """
    if raw is None:
        return None
    value = raw.strip()
    if value == "":
        raise ADConfigError(f"{name} must be a non-empty string when set.")
    return value


def _parse_int(raw: str | None, *, default: int, name: str) -> int:
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:  # noqa: PERF203
        raise ADConfigError(f"{name} must be an integer (got {raw!r})") from exc


@dataclass(frozen=True)
class ADConfig:
    """Resolved AD connection configuration."""

    server: str
    base_dn: str
    bind_user: str
    # Excluded from repr so credentials never leak into logs/tracebacks.
    bind_password: str = field(repr=False)
    port: int = 636
    use_ssl: bool = True
    ca_certs: str | None = None
    tls_validate: bool = True
    page_size: int = 500
    # Optional scoped search bases. When set, find_users/get_user-by-name and the
    # bulk user-index build search user_search_base; find_computers and the bulk
    # computer sweep search computer_search_base. Both default to base_dn.
    user_search_base: str | None = None
    computer_search_base: str | None = None

    @property
    def effective_user_search_base(self) -> str:
        """The base to search for user objects (user_search_base or base_dn)."""
        return self.user_search_base or self.base_dn

    @property
    def effective_computer_search_base(self) -> str:
        """The base to search for computer objects (computer_search_base or base_dn)."""
        return self.computer_search_base or self.base_dn

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "ADConfig":
        """Build a config from a mapping (defaults to ``os.environ``)."""
        env = os.environ if env is None else env

        missing = [name for name in _REQUIRED if not (env.get(name) or "").strip()]
        if missing:
            raise ADConfigError(
                "Missing required environment variable(s): " + ", ".join(sorted(missing))
            )

        use_ssl = _parse_bool(env.get(ENV_USE_SSL), default=True, name=ENV_USE_SSL)
        if not use_ssl:
            # LDAPS is mandatory (locked design decision): a SIMPLE bind without SSL
            # would send AD_BIND_PASSWORD in cleartext. The only sanctioned relaxation
            # for the self-signed lab DC is AD_TLS_VALIDATE=false.
            raise ADConfigError(
                f"{ENV_USE_SSL}=false is not supported: LDAPS is mandatory because "
                "SIMPLE bind would transmit the password in cleartext. For a "
                f"self-signed lab DC, keep SSL on and set {ENV_TLS_VALIDATE}=false instead."
            )

        return cls(
            server=env[ENV_SERVER].strip(),
            base_dn=env[ENV_BASE_DN].strip(),
            bind_user=env[ENV_BIND_USER].strip(),
            bind_password=env[ENV_BIND_PASSWORD],
            port=_parse_int(env.get(ENV_PORT), default=636, name=ENV_PORT),
            use_ssl=use_ssl,
            ca_certs=(env.get(ENV_CA_CERTS) or "").strip() or None,
            tls_validate=_parse_bool(env.get(ENV_TLS_VALIDATE), default=True, name=ENV_TLS_VALIDATE),
            page_size=_parse_int(env.get(ENV_PAGE_SIZE), default=500, name=ENV_PAGE_SIZE),
            user_search_base=_parse_optional_str(
                env.get(ENV_USER_SEARCH_BASE), name=ENV_USER_SEARCH_BASE
            ),
            computer_search_base=_parse_optional_str(
                env.get(ENV_COMPUTER_SEARCH_BASE), name=ENV_COMPUTER_SEARCH_BASE
            ),
        )
