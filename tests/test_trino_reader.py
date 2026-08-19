"""Trino read-only SQL 도구 검증 — 쓰기 SQL 거부·인젝션 차단·REST 폴링 (mock)."""

from __future__ import annotations

import pytest

from src.tools.trino_reader import (
    TrinoClient,
    TrinoConfig,
    TrinoQueryError,
    _ident,
    assert_readonly_sql,
    make_trino_tools,
)


@pytest.mark.parametrize("sql", [
    "SELECT * FROM t LIMIT 10",
    "with x as (select 1) select * from x",
    "SHOW CATALOGS",
    "DESCRIBE delta.bronze.events",
    "EXPLAIN SELECT count(*) FROM t",
])
def test_readonly_sql_allowed(sql):
    assert assert_readonly_sql(sql)


@pytest.mark.parametrize("sql", [
    "INSERT INTO t VALUES (1)",
    "UPDATE t SET x=1",
    "DELETE FROM t",
    "DROP TABLE t",
    "CREATE TABLE t (a int)",
    "ALTER TABLE t ADD COLUMN b int",
    "TRUNCATE TABLE t",
    "GRANT SELECT ON t TO u",
    "CALL system.runtime.kill_query('x')",
    "SELECT 1; DROP TABLE t",              # 다중 문장
    "SELECT 1 /* hi */; INSERT INTO t VALUES(1)",
    "select * from t; delete from t",
    "WITH x AS (SELECT 1) INSERT INTO t SELECT * FROM x",  # CTE 뒤 쓰기
])
def test_write_sql_rejected(sql):
    with pytest.raises(TrinoQueryError):
        assert_readonly_sql(sql)


def test_comment_stripping_prevents_bypass():
    # 주석으로 쓰기를 숨기려는 시도
    with pytest.raises(TrinoQueryError):
        assert_readonly_sql("SELECT 1 --\n; DROP TABLE t")
    with pytest.raises(TrinoQueryError):
        assert_readonly_sql("/* select */ DROP TABLE t")


def test_identifier_injection_blocked():
    assert _ident("delta") == "delta"
    for bad in ("a; drop", "a.b", "a'", "1abc", "a-b", "a b"):
        with pytest.raises(TrinoQueryError):
            _ident(bad)


class FakeResp:
    def __init__(self, payload, status=200):
        self._p, self.status_code, self.text = payload, status, str(payload)

    def json(self):
        return self._p


class FakeHttp:
    """Trino REST 폴링(nextUri)을 흉내내는 mock httpx client."""

    def __init__(self, pages):
        self.pages = list(pages)
        self.posted = None
        self.deleted = []

    def post(self, url, content=None, headers=None):
        self.posted = content.decode() if isinstance(content, bytes) else content
        return FakeResp(self.pages[0])

    def get(self, url, headers=None):
        return FakeResp(self.pages[self._idx])

    def delete(self, url, headers=None):
        self.deleted.append(url)
        return FakeResp({})

    _idx = 1

    def close(self):
        pass


def test_client_polls_and_returns_rows():
    pages = [
        {"columns": [{"name": "n"}], "data": [[1], [2]], "nextUri": "u2"},
        {"data": [[3]], "nextUri": None},
    ]
    fake = FakeHttp(pages)
    client = TrinoClient(TrinoConfig(endpoint="http://trino:8080", user="a"), http_client=fake)
    res = client.query("SELECT n FROM t")
    assert res["columns"] == ["n"]
    assert res["rows"] == [[1], [2], [3]]
    assert res["row_count"] == 3


def test_client_rejects_write_before_network():
    fake = FakeHttp([{"data": [], "nextUri": None}])
    client = TrinoClient(TrinoConfig(endpoint="http://trino:8080"), http_client=fake)
    with pytest.raises(TrinoQueryError):
        client.query("DROP TABLE t")
    assert fake.posted is None  # 네트워크 전에 거부


def test_client_surfaces_trino_error():
    fake = FakeHttp([{"error": {"message": "TABLE_NOT_FOUND"}, "nextUri": None}])
    client = TrinoClient(TrinoConfig(endpoint="http://trino:8080"), http_client=fake)
    with pytest.raises(TrinoQueryError, match="TABLE_NOT_FOUND"):
        client.query("SELECT * FROM missing")


def test_tools_registered_readonly():
    from src.tools import verb_validator

    tools = make_trino_tools(TrinoConfig(endpoint="http://trino:8080"))
    names = {t.name for t in tools}
    assert names == {
        "trino_query", "trino_catalogs", "trino_schemas", "trino_tables", "trino_describe",
        "trino_sample", "trino_count", "trino_profile", "trino_table_profile", "trino_freshness",
    }
    reg = verb_validator.registered_tools()
    for n in names:
        assert reg[n].verb == "sql-read"


def test_profiling_tools_build_correct_sql():
    """편의 도구(sample/count/profile)가 검증된 식별자로 read-only SQL을 만드는지."""
    calls: list[str] = []

    import src.tools.trino_reader as tr

    class Fake:
        def query(self, sql, max_rows=200):
            calls.append(sql)
            return {"columns": ["c"], "rows": [[1]], "row_count": 1, "truncated": False}

    orig = tr.TrinoClient
    tr.TrinoClient = lambda config: Fake()  # type: ignore[assignment]
    try:
        tools = {t.name: t for t in tr.make_trino_tools(TrinoConfig(endpoint="http://trino:8080"))}
        tools["trino_count"].invoke({"catalog": "delta", "schema": "silver", "table": "events"})
        tools["trino_sample"].invoke({"catalog": "delta", "schema": "silver", "table": "events", "limit": 5})
        tools["trino_profile"].invoke({"catalog": "delta", "schema": "silver", "table": "events", "column": "user_id"})
    finally:
        tr.TrinoClient = orig  # type: ignore[assignment]

    assert any("COUNT(*)" in c and "delta.silver.events" in c for c in calls)
    assert any("LIMIT 5" in c for c in calls)
    assert any("COUNT(DISTINCT user_id)" in c for c in calls)
    # 만들어진 SQL은 전부 read-only여야 한다
    for c in calls:
        assert assert_readonly_sql(c)


def test_profiling_tools_reject_injection_identifier():
    """편의 도구도 _ident로 인젝션 식별자를 거부한다(쿼리 미실행)."""
    import src.tools.trino_reader as tr

    tr.TrinoClient = lambda config: None  # type: ignore[assignment]
    tools = {t.name: t for t in tr.make_trino_tools(TrinoConfig(endpoint="http://trino:8080"))}
    with pytest.raises(TrinoQueryError):
        tools["trino_profile"].func(catalog="delta", schema="silver", table="events", column="x); DROP")


def test_data_analyst_agent_maps_trino_tools():
    from src.agents import load_agents
    from pathlib import Path

    agents = load_agents(Path(__file__).resolve().parent.parent / ".agents")
    da = agents.get("data-analyst")
    assert da is not None
    assert "trino_query" in da.tools and "trino_tables" in da.tools
    assert "lakehouse" in da.instructions.lower() or "lake" in da.instructions.lower()
