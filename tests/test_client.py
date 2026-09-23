"""Unit tests for story-001: config, LDAPS client, dry-run/diff write framework.

These run fully offline. The connection-bound behaviour (diff_modify,
check_connection) is exercised against ldap3's MOCK_SYNC strategy with the
bundled offline AD schema, so no live DC is required. Live-DC coverage lives in
scripts/smoke_connection.py.
"""

import ssl

import pytest
from ldap3 import BASE, MOCK_SYNC, OFFLINE_AD_2012_R2, Connection, Server

import config as config_mod
from config import ADConfig
from ad_client import ADClient, compute_diff


BASE_DN = "DC=lab,DC=example,DC=com"
BIND_DN = "CN=svc_ldap,OU=Service,DC=lab,DC=example,DC=com"
USER_DN = "CN=jdoe,OU=Users,DC=lab,DC=example,DC=com"


def _env(**overrides):
    base = {
        "AD_SERVER": "dc01.lab.example.com",
        "AD_BASE_DN": BASE_DN,
        "AD_BIND_USER": BIND_DN,
        "AD_BIND_PASSWORD": "s3cret",
    }
    base.update(overrides)
    return base


# --------------------------------------------------------------------------- #
# ADConfig.from_env
# --------------------------------------------------------------------------- #

def test_config_defaults():
    cfg = ADConfig.from_env(_env())
    assert cfg.server == "dc01.lab.example.com"
    assert cfg.base_dn == BASE_DN
    assert cfg.bind_user == BIND_DN
    assert cfg.port == 636
    assert cfg.use_ssl is True
    assert cfg.tls_validate is True  # validation defaults ON
    assert cfg.page_size == 500
    assert cfg.ca_certs is None


def test_config_tls_validate_optout():
    for val in ("false", "False", "0", "no", "off"):
        cfg = ADConfig.from_env(_env(AD_TLS_VALIDATE=val))
        assert cfg.tls_validate is False, val


def test_config_tls_validate_truthy():
    for val in ("true", "TRUE", "1", "yes", "on"):
        cfg = ADConfig.from_env(_env(AD_TLS_VALIDATE=val))
        assert cfg.tls_validate is True, val


def test_config_overrides():
    cfg = ADConfig.from_env(
        _env(AD_PORT="3269", AD_PAGE_SIZE="100", AD_CA_CERTS="/etc/ca.pem")
    )
    assert cfg.port == 3269
    assert cfg.page_size == 100
    assert cfg.ca_certs == "/etc/ca.pem"
    assert cfg.use_ssl is True


def test_config_scoped_search_bases_default_to_base_dn():
    cfg = ADConfig.from_env(_env())
    assert cfg.user_search_base is None
    assert cfg.computer_search_base is None
    # The effective accessors fall back to base_dn when unset.
    assert cfg.effective_user_search_base == BASE_DN
    assert cfg.effective_computer_search_base == BASE_DN


def test_config_scoped_search_bases_when_set():
    user_base = f"OU=_Users,{BASE_DN}"
    comp_base = f"OU=_Computers,{BASE_DN}"
    cfg = ADConfig.from_env(
        _env(AD_USER_SEARCH_BASE=user_base, AD_COMPUTER_SEARCH_BASE=comp_base)
    )
    assert cfg.user_search_base == user_base
    assert cfg.computer_search_base == comp_base
    assert cfg.effective_user_search_base == user_base
    assert cfg.effective_computer_search_base == comp_base


@pytest.mark.parametrize("var", ["AD_USER_SEARCH_BASE", "AD_COMPUTER_SEARCH_BASE"])
def test_config_scoped_search_base_blank_rejected(var):
    # Present-but-blank is a mistake — fail loudly rather than silently using base_dn.
    with pytest.raises(config_mod.ADConfigError) as exc:
        ADConfig.from_env(_env(**{var: "   "}))
    assert var in str(exc.value)


def test_config_rejects_ssl_optout():
    # LDAPS is mandatory: disabling SSL would send the bind password cleartext.
    with pytest.raises(config_mod.ADConfigError) as exc:
        ADConfig.from_env(_env(AD_USE_SSL="false"))
    assert "LDAPS" in str(exc.value)
    assert "AD_TLS_VALIDATE" in str(exc.value)


@pytest.mark.parametrize("missing", ["AD_SERVER", "AD_BASE_DN", "AD_BIND_USER", "AD_BIND_PASSWORD"])
def test_config_missing_required_raises(missing):
    env = _env()
    del env[missing]
    with pytest.raises(config_mod.ADConfigError) as exc:
        ADConfig.from_env(env)
    assert missing in str(exc.value)


def test_config_never_repr_password():
    cfg = ADConfig.from_env(_env(AD_BIND_PASSWORD="topsecret"))
    assert "topsecret" not in repr(cfg)


# --------------------------------------------------------------------------- #
# TLS construction — validation default + opt-out
# --------------------------------------------------------------------------- #

def test_build_server_tls_validate_on(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")
    client = ADClient(ADConfig.from_env(_env(AD_CA_CERTS=str(ca))))
    server = client.build_server()
    assert server.tls.validate == ssl.CERT_REQUIRED
    assert server.tls.ca_certs_file == str(ca)
    assert server.ssl is True


def test_build_server_tls_validate_off():
    client = ADClient(ADConfig.from_env(_env(AD_TLS_VALIDATE="false")))
    server = client.build_server()
    assert server.tls.validate == ssl.CERT_NONE


# --------------------------------------------------------------------------- #
# compute_diff — pure before/after diff
# --------------------------------------------------------------------------- #

def test_compute_diff_changed_only():
    before = {"title": ["Eng"], "department": ["IT"]}
    after = {"title": ["Manager"], "department": ["IT"]}
    diff = compute_diff(before, after)
    assert diff == {"title": {"before": ["Eng"], "after": ["Manager"]}}


def test_compute_diff_clear_attribute():
    diff = compute_diff({"description": ["old"]}, {"description": []})
    assert diff == {"description": {"before": ["old"], "after": []}}


def test_compute_diff_add_attribute():
    diff = compute_diff({"title": []}, {"title": ["New"]})
    assert diff == {"title": {"before": [], "after": ["New"]}}


def test_compute_diff_no_change_is_empty():
    assert compute_diff({"title": ["Eng"]}, {"title": ["Eng"]}) == {}


# --------------------------------------------------------------------------- #
# diff_modify — dry-run returns diff without committing; live commits
# --------------------------------------------------------------------------- #

@pytest.fixture
def mock_client():
    server = Server("fake-dc", get_info=OFFLINE_AD_2012_R2)
    conn = Connection(server, user=BIND_DN, password="s3cret", client_strategy=MOCK_SYNC)
    conn.strategy.add_entry(
        BIND_DN, {"objectClass": ["user"], "sAMAccountName": "svc_ldap", "userPassword": "s3cret"}
    )
    conn.strategy.add_entry(
        USER_DN,
        {
            "objectClass": ["user"],
            "sAMAccountName": "jdoe",
            "title": ["Engineer"],
            "department": ["IT"],
        },
    )
    conn.bind()
    cfg = ADConfig.from_env(_env())
    return ADClient(cfg, connection=conn)


def _read_title(conn):
    conn.search(USER_DN, "(objectClass=*)", search_scope=BASE, attributes=["title"])
    return conn.entries[0].title.value


def test_diff_modify_dry_run_returns_diff_without_committing(mock_client):
    result = mock_client.diff_modify(USER_DN, {"title": ["Manager"]}, dry_run=True)

    assert result["dry_run"] is True
    assert result["committed"] is False
    assert result["changes"] == {"title": {"before": ["Engineer"], "after": ["Manager"]}}
    # Nothing was actually written.
    assert _read_title(mock_client.conn) == "Engineer"


def test_diff_modify_commit_writes(mock_client):
    result = mock_client.diff_modify(USER_DN, {"title": ["Manager"]}, dry_run=False)

    assert result["dry_run"] is False
    assert result["committed"] is True
    assert _read_title(mock_client.conn) == "Manager"


def test_diff_modify_dry_run_noop_when_unchanged(mock_client):
    result = mock_client.diff_modify(USER_DN, {"title": ["Engineer"]}, dry_run=True)
    assert result["changes"] == {}
    assert result["committed"] is False


def test_diff_modify_default_is_dry_run(mock_client):
    # Safety posture: omitting dry_run must NOT write.
    result = mock_client.diff_modify(USER_DN, {"title": ["Manager"]})
    assert result["dry_run"] is True
    assert result["committed"] is False
    assert _read_title(mock_client.conn) == "Engineer"


# --------------------------------------------------------------------------- #
# check_connection
# --------------------------------------------------------------------------- #

def test_check_connection_reports_server_and_bind(mock_client):
    info = mock_client.check_connection()
    assert info["connected"] is True
    assert info["server"] == "dc01.lab.example.com"
    assert info["base_dn"] == BASE_DN
    assert info["bind_user"] == BIND_DN
    assert info["tls_validate"] is True
    # whoami present as a key even when the mock can't answer it.
    assert "whoami" in info
    assert "server_info" in info
