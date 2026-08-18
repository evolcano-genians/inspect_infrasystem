"""read-only Trino SQL 분석 도구 — nexus-lake(Delta lakehouse) 데이터 조회.

nexus-lake는 Kafka→Delta bronze/silver 테이블을 Trino로 조회하는 lakehouse다.
이 도구는 **조회(SELECT/SHOW/DESCRIBE/EXPLAIN)만** 허용한다 — 데이터 정의·조작
(CREATE/INSERT/UPDATE/DELETE/DROP 등)은 SQL 파싱 단계에서 거부된다.

연결은 설정으로 주입한다 (자격증명 하드코딩 없음):
  TRINO_ENDPOINT=http://localhost:8080   # 사용자가 port-forward 하거나 도달 가능한 주소
  TRINO_USER=analyst
  TRINO_TOKEN=<JWT>                       # JWT 인증 시 (선택)
Trino REST API(POST /v1/statement + nextUri 폴링)를 직접 사용한다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: 선두 키워드가 이 집합이어야만 실행을 허용한다 (조회 전용).
_READONLY_LEADS = frozenset({"select", "with", "show", "describe", "desc", "explain", "values", "table"})
#: 명시적 금지 키워드 (문장 어디에 있어도 거부 — CTE·서브쿼리 우회 차단)
_FORBIDDEN = (
    "insert", "update", "delete", "merge", "create", "drop", "alter", "truncate",
    "grant", "revoke", "call", "comment", "set ", "use ", "start ", "commit",
    "rollback", "prepare", "execute", "deallocate", "reset ", "refresh",
)
_MAX_ROWS = 1000
_MAX_SQL_LEN = 20_000


class TrinoQueryError(RuntimeError):
    pass


def _strip_sql(sql: str) -> str:
    """주석(-- , /* */)과 잉여 공백을 제거해 검증을 우회 못하게 한다."""
    no_block = re.sub(r"/\*.*?\*/", " ", sql, flags=re.DOTALL)
    no_line = re.sub(r"--[^\n]*", " ", no_block)
    return no_line.strip()


def assert_readonly_sql(sql: str) -> str:
    """조회 전용 SQL인지 결정론적으로 검증한다. 위반 시 TrinoQueryError. O(len)."""
    if not sql or not sql.strip():
        raise TrinoQueryError("빈 SQL")
    if len(sql) > _MAX_SQL_LEN:
        raise TrinoQueryError("SQL이 너무 깁니다")
    cleaned = _strip_sql(sql)
    # 다중 문장 금지 (마지막 세미콜론 1개만 허용)
    if cleaned.rstrip(";").count(";") > 0:
        raise TrinoQueryError("다중 SQL 문장은 허용되지 않습니다 (한 번에 하나의 조회만)")
    body = cleaned.rstrip(";").strip()
    lead = body.split(None, 1)[0].lower() if body else ""
    if lead not in _READONLY_LEADS:
        raise TrinoQueryError(
            f"조회 전용 SQL만 허용됩니다. 선두 '{lead}' 불가 "
            f"(허용: {sorted(_READONLY_LEADS)})"
        )
    lowered = " " + body.lower() + " "
    for kw in _FORBIDDEN:
        # 단어 경계로 확인 (identifier에 우연히 포함된 경우는 제외)
        if re.search(r"(?<![a-z_])" + re.escape(kw.strip()) + r"(?![a-z_])", lowered):
            raise TrinoQueryError(f"금지 키워드 '{kw.strip()}' 가 포함되어 거부되었습니다")
    return body


@dataclass(frozen=True)
class TrinoConfig:
    endpoint: str
    user: str = "inspect-k8s"
    token: str = ""
    catalog: str = ""
    schema: str = ""


class TrinoClient:
    """Trino REST API read-only 클라이언트 (httpx)."""

    def __init__(self, config: TrinoConfig, *, http_client=None):
        if not re.match(r"^https?://[^\s]+$", config.endpoint or ""):
            raise TrinoQueryError(f"TRINO_ENDPOINT 형식 오류: {config.endpoint!r}")
        self.config = config
        self._client = http_client

    def _headers(self) -> dict:
        h = {"X-Trino-User": self.config.user}
        if self.config.catalog:
            h["X-Trino-Catalog"] = self.config.catalog
        if self.config.schema:
            h["X-Trino-Schema"] = self.config.schema
        if self.config.token:
            h["Authorization"] = f"Bearer {self.config.token}"
        return h

    def query(self, sql: str, *, max_rows: int = _MAX_ROWS, timeout: float = 60.0) -> dict:
        """조회 SQL을 실행하고 컬럼·행(상한 max_rows)을 반환한다. 검증 통과 필수."""
        body = assert_readonly_sql(sql)
        max_rows = max(1, min(int(max_rows), _MAX_ROWS))
        import httpx

        client = self._client or httpx.Client(timeout=timeout)
        columns: list[str] = []
        rows: list[list] = []
        try:
            resp = client.post(
                f"{self.config.endpoint.rstrip('/')}/v1/statement",
                content=body.encode("utf-8"),
                headers=self._headers(),
            )
            data = _json(resp)
            while True:
                if data.get("columns") and not columns:
                    columns = [c["name"] for c in data["columns"]]
                for r in data.get("data") or []:
                    if len(rows) < max_rows:
                        rows.append(r)
                err = data.get("error")
                if err:
                    raise TrinoQueryError(
                        f"Trino 오류: {err.get('message', '')[:300]}"
                    )
                next_uri = data.get("nextUri")
                if not next_uri or len(rows) >= max_rows:
                    # 남은 결과는 취소(cancel)해 서버 부하를 줄인다 (DELETE는 쿼리 취소 — 데이터 아님)
                    if next_uri and self.config.endpoint:
                        try:
                            client.delete(next_uri, headers=self._headers())
                        except Exception:
                            pass
                    break
                data = _json(client.get(next_uri, headers=self._headers()))
        finally:
            if self._client is None:
                client.close()
        return {"columns": columns, "rows": rows, "row_count": len(rows),
                "truncated": len(rows) >= max_rows}


def _json(resp) -> dict:
    if resp.status_code >= 400:
        raise TrinoQueryError(f"HTTP {resp.status_code}: {resp.text[:300]}")
    return resp.json()


def _fmt(result: dict, sql_label: str = "") -> str:
    cols = result.get("columns") or []
    rows = result.get("rows") or []
    head = f"{sql_label}\n" if sql_label else ""
    if not cols:
        return head + "(결과 없음)"
    lines = [" | ".join(map(str, cols))]
    for r in rows[:200]:
        lines.append(" | ".join("" if v is None else str(v) for v in r))
    tail = f"\n...[{result['row_count']}행{' (상한 도달)' if result.get('truncated') else ''}]"
    return head + "\n".join(lines) + tail


def make_trino_tools(config: TrinoConfig, audit=None) -> list:
    import time

    from langchain_core.tools import StructuredTool

    from . import verb_validator

    client = TrinoClient(config)

    def _run(tool_name: str, sql: str, max_rows: int = 200) -> str:
        verb_validator.register_tool(tool_name, "sql-read", "trino")
        started = time.perf_counter()
        try:
            result = client.query(sql, max_rows=max_rows)
        except TrinoQueryError as exc:
            if audit:
                audit.record(tool=tool_name, verb="sql-read", resource="trino",
                             allowed=False, reason=str(exc))
            return f"[거부됨 · read-only SQL 정책] {exc}"
        except Exception as exc:
            return f"[Trino 조회 오류] {type(exc).__name__}: {exc}"
        if audit:
            audit.record(tool=tool_name, verb="sql-read", resource="trino", allowed=True,
                         duration_ms=(time.perf_counter() - started) * 1000,
                         result_chars=result["row_count"])
        return _fmt(result)

    def _fqtn(catalog: str, schema: str, table: str) -> str:
        """검증된 catalog.schema.table 완전수식명 — 각 식별자는 _ident로 인젝션 차단."""
        return f"{_ident(catalog)}.{_ident(schema)}.{_ident(table)}"

    def _sample(catalog, schema, table, limit=20):
        n = max(1, min(int(limit), 100))
        return _run("trino_sample", f"SELECT * FROM {_fqtn(catalog, schema, table)} LIMIT {n}", n)

    def _count(catalog, schema, table):
        return _run("trino_count",
                    f"SELECT COUNT(*) AS row_count FROM {_fqtn(catalog, schema, table)}")

    def _profile(catalog, schema, table, column):
        col = _ident(column)
        fq = _fqtn(catalog, schema, table)
        # 단일 컬럼 프로파일: 총건수·비널·널·고유값·최소·최대 (한 번의 스캔 집계)
        sql = (
            f"SELECT COUNT(*) AS total, COUNT({col}) AS non_null, "
            f"COUNT(*) - COUNT({col}) AS nulls, COUNT(DISTINCT {col}) AS distinct_vals, "
            f"MIN({col}) AS min_v, MAX({col}) AS max_v FROM {fq}"
        )
        return _run("trino_profile", sql)

    # 도구 등록 (모두 read-only)
    for name in ("trino_query", "trino_catalogs", "trino_schemas", "trino_tables",
                 "trino_describe", "trino_sample", "trino_count", "trino_profile"):
        verb_validator.register_tool(name, "sql-read", "trino")

    tools = [
        StructuredTool.from_function(
            func=lambda sql, max_rows=200: _run("trino_query", sql, max_rows),
            name="trino_query",
            description="nexus-lake lakehouse에 read-only SQL 조회를 실행한다 "
                        "(SELECT/WITH/SHOW/DESCRIBE/EXPLAIN만, 쓰기 SQL 거부). "
                        "Delta bronze/silver 테이블 데이터 분석용. max_rows로 행 제한.",
        ),
        StructuredTool.from_function(
            func=lambda: _run("trino_catalogs", "SHOW CATALOGS"),
            name="trino_catalogs", description="Trino 카탈로그 목록을 조회한다.",
        ),
        StructuredTool.from_function(
            func=lambda catalog: _run("trino_schemas", f"SHOW SCHEMAS FROM {_ident(catalog)}"),
            name="trino_schemas", description="카탈로그의 스키마 목록을 조회한다.",
        ),
        StructuredTool.from_function(
            func=lambda catalog, schema: _run(
                "trino_tables", f"SHOW TABLES FROM {_ident(catalog)}.{_ident(schema)}"),
            name="trino_tables", description="스키마의 테이블 목록을 조회한다.",
        ),
        StructuredTool.from_function(
            func=lambda catalog, schema, table: _run(
                "trino_describe", f"DESCRIBE {_ident(catalog)}.{_ident(schema)}.{_ident(table)}"),
            name="trino_describe", description="테이블의 컬럼 스키마를 조회한다.",
        ),
        StructuredTool.from_function(
            func=_sample, name="trino_sample",
            description="테이블에서 샘플 행을 미리 본다 (SELECT * LIMIT n, 기본 20). "
                        "데이터 형태·값 분포를 빠르게 감 잡을 때 사용. 대량 스캔 없이 안전.",
        ),
        StructuredTool.from_function(
            func=_count, name="trino_count",
            description="테이블의 전체 행 수를 센다 (SELECT COUNT(*)). 적재량·파이프라인 상태 확인용.",
        ),
        StructuredTool.from_function(
            func=_profile, name="trino_profile",
            description="한 컬럼을 프로파일링한다: 총건수·비널·널·고유값 수·최소·최대를 한 번에. "
                        "데이터 품질(널 비율·카디널리티)·이상치 파악에 사용. column 인자로 대상 컬럼 지정.",
        ),
    ]
    return tools


_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


def _ident(name: str) -> str:
    """카탈로그/스키마/테이블 식별자 검증 — SQL 인젝션 차단."""
    if not isinstance(name, str) or not _IDENT_RE.match(name):
        raise TrinoQueryError(f"유효하지 않은 식별자: {name!r}")
    return name
