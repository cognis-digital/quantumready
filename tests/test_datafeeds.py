"""Offline tests for the bundled datafeeds ingester: catalog parsing, cache
freshness, offline serve, the air-gap snapshot round-trip, and the feeds
allowlist. NO NETWORK — every call uses offline=True or a temp cache dir.
"""
import importlib
import json
from pathlib import Path

import pytest

FIX = Path(__file__).resolve().parent / "fixtures" / "feeds-cache"


@pytest.fixture
def df(monkeypatch, tmp_path):
    """datafeeds bound to a fresh, empty temp cache dir."""
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))
    import quantumready.datafeeds as mod
    importlib.reload(mod)
    return mod


@pytest.fixture
def df_fixtures(monkeypatch):
    """datafeeds bound to the committed populated fixture cache."""
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(FIX))
    import quantumready.datafeeds as mod
    importlib.reload(mod)
    return mod


# --------------------------------------------------------------------------- #
# catalog
# --------------------------------------------------------------------------- #
def test_catalog_loads_and_has_feeds(df):
    cat = df.load_catalog()
    assert "feeds" in cat
    assert len(cat["feeds"]) >= 1


def test_catalog_feeds_have_required_keys(df):
    for f in df.load_catalog()["feeds"]:
        assert "id" in f and "url" in f and "name" in f


def test_catalog_contains_the_two_quantumready_feeds(df):
    ids = {f["id"] for f in df.load_catalog()["feeds"]}
    assert {"cisa-kev", "nvd-cve"} <= ids


def test_list_feeds_domain_filter(df):
    feeds = df.load_catalog()["feeds"]
    domains = {f.get("domain") for f in feeds if f.get("domain")}
    if domains:
        d = next(iter(domains))
        filtered = df.list_feeds(domain=d)
        assert all(f.get("domain") == d for f in filtered)


# --------------------------------------------------------------------------- #
# cache freshness
# --------------------------------------------------------------------------- #
def test_cached_age_none_when_empty(df):
    assert df.cached_age_hours("cisa-kev") is None


def test_cache_dir_created(df, tmp_path):
    assert df.cache_dir() == tmp_path
    assert tmp_path.exists()


def test_offline_get_without_cache_raises(df):
    with pytest.raises(FileNotFoundError):
        df.get("cisa-kev", offline=True)


# --------------------------------------------------------------------------- #
# offline serve from fixtures
# --------------------------------------------------------------------------- #
def test_offline_get_serves_json(df_fixtures):
    kev = df_fixtures.get("cisa-kev", offline=True)
    assert isinstance(kev, dict)
    assert kev["vulnerabilities"]


def test_cached_age_present_for_fixtures(df_fixtures):
    age = df_fixtures.cached_age_hours("cisa-kev")
    assert age is not None and age >= 0


# --------------------------------------------------------------------------- #
# air-gap snapshot round-trip (no network, temp dirs only)
# --------------------------------------------------------------------------- #
def test_snapshot_export_import_round_trip(df, tmp_path, monkeypatch):
    # seed a fake cached feed in the temp cache
    data_path, meta_path = df._paths("cisa-kev")
    data_path.write_bytes(json.dumps({"vulnerabilities": [{"cveID": "CVE-2024-0001"}]}).encode())
    meta_path.write_text(json.dumps({"feed": "cisa-kev", "fetched_at": 0, "bytes": 10}))

    archive = tmp_path / "snap.tar.gz"
    n = df.snapshot_export(str(archive))
    assert n == 1
    assert archive.exists()

    # import into a different empty cache dir
    dest = tmp_path / "enclave"
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(dest))
    importlib.reload(df)
    imported = df.snapshot_import(str(archive))
    assert imported == 1
    served = df.get("cisa-kev", offline=True)
    assert served["vulnerabilities"][0]["cveID"] == "CVE-2024-0001"


def test_snapshot_import_ignores_path_traversal_names(df, tmp_path):
    # craft an archive whose member name contains a traversal prefix; import must
    # collapse to basename and never escape the cache dir.
    import tarfile
    import io

    archive = tmp_path / "evil.tar.gz"
    payload = json.dumps({"vulnerabilities": []}).encode()
    with tarfile.open(archive, "w:gz") as tar:
        info = tarfile.TarInfo(name="../../escape.data")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    df.snapshot_import(str(archive))
    # nothing should have been written outside the cache dir
    assert not (tmp_path.parent / "escape.data").exists()
    assert (df.cache_dir() / "escape.data").exists()


# --------------------------------------------------------------------------- #
# CLI of datafeeds module (offline paths only)
# --------------------------------------------------------------------------- #
def test_datafeeds_cli_list(df_fixtures, capsys):
    rc = df_fixtures.main(["list"])
    assert rc == 0
    assert "cisa-kev" in capsys.readouterr().out


def test_datafeeds_cli_get_offline(df_fixtures, capsys):
    rc = df_fixtures.main(["get", "cisa-kev", "--offline"])
    assert rc == 0
    assert "vulnerabilities" in capsys.readouterr().out


def test_datafeeds_cli_get_unknown_offline_errors(df, capsys):
    rc = df.main(["get", "does-not-exist", "--offline"])
    assert rc == 1
