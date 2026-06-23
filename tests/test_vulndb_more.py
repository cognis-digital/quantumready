"""Additional offline tests for the bundled 262k-vuln OSV database loader.

These pin the lazy-loading, indexing, and lookup semantics of vulndb_local.VulnDB
against the real bundled gz. All offline, stdlib only.
"""
from quantumready.vulndb_local import VulnDB, count


def test_module_count_matches_instance():
    db = VulnDB()
    assert count() == db.count()


def test_count_is_large_real_corpus():
    assert VulnDB().count() >= 100000


def test_load_is_cached_same_object():
    db = VulnDB()
    a = db.load()
    b = db.load()
    assert a is b  # second call returns the cached list


def test_iter_yields_dicts():
    it = iter(VulnDB())
    first = next(it)
    assert isinstance(first, dict)
    assert first.get("id")


def test_records_have_expected_keys():
    r = next(iter(VulnDB()))
    for key in ("id", "aliases", "ecosystem", "summary", "severity", "packages"):
        assert key in r


def test_by_cve_returns_list_for_unknown():
    assert VulnDB().by_cve("CVE-0000-00000") == []


def test_by_cve_is_case_insensitive():
    db = VulnDB()
    # find some record that has a CVE alias to test case-insensitivity
    sample = None
    for rec in db:
        for alias in (rec.get("aliases") or []):
            if alias.upper().startswith("CVE-"):
                sample = alias
                break
        if sample:
            break
    if sample:
        assert db.by_cve(sample.lower()) == db.by_cve(sample.upper())


def test_by_package_unknown_is_empty():
    assert VulnDB().by_package("this-package-does-not-exist-xyz") == []


def test_by_package_known_returns_hits():
    db = VulnDB()
    assert db.by_package("lodash") or db.by_package("django") or db.by_package("log4j-core")


def test_by_package_ecosystem_filter_consistency():
    db = VulnDB()
    for name in ("lodash", "django", "log4j-core"):
        hits = db.by_package(name)
        if hits:
            eco = hits[0].get("ecosystem")
            if eco:
                filtered = db.by_package(name, ecosystem=eco)
                assert all(r.get("ecosystem", "").lower() == eco.lower() for r in filtered)
            break


def test_search_respects_limit():
    res = VulnDB().search("the", limit=5)
    assert len(res) <= 5


def test_search_empty_query_returns_list():
    assert isinstance(VulnDB().search("", limit=3), list)


def test_search_matches_summary_substring():
    res = VulnDB().search("overflow", limit=10)
    for r in res:
        assert "overflow" in (r.get("summary", "") or "").lower()


def test_missing_db_path_is_safe(tmp_path):
    db = VulnDB(path=str(tmp_path / "nope.jsonl.gz"))
    assert db.count() == 0
    assert list(db) == []
    assert db.by_cve("CVE-2021-44228") == []
