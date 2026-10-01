from __future__ import annotations

import datetime
import decimal
from collections.abc import Iterator
from contextlib import contextmanager

_STATEMENT_TIMEOUT_MS = 5000

CURRENT_GENERATION_SQL = "SELECT gen_id FROM kb.load_generation WHERE is_current"

PRODUCT_ROWS_SQL = """
SELECT a.advisory_id                                   AS advisory_id,
       COALESCE(NULLIF(ap.cve_id, ''), bundle.cve_id)  AS cve_id,
       (COALESCE(ap.cve_id, '') <> '')                 AS cve_specific,
       p.product_clean                                 AS product_clean,
       ap.affected_range, ap.fixed_version_clean,
       ap.status,
       (length(btrim(COALESCE(ap.evidence_quote, ''))) > 0) AS has_quote,
       a.severity, a.cvss, a.known_exploited, a.url, a.published,
       c.epss, c.in_cisa_kev, c.kev_due_date
FROM kb.advisory_product ap
JOIN kb.advisory a        ON a.advisory_pk = ap.advisory_pk AND a.valid_to IS NULL
JOIN kb.product p         ON p.product_pk = ap.product_pk
JOIN kb.load_generation g ON g.gen_id = a.gen_id AND g.is_current
LEFT JOIN kb.cve c        ON c.cve_id = COALESCE(NULLIF(ap.cve_id, ''), '')
LEFT JOIN LATERAL (
    SELECT ac.cve_id FROM kb.advisory_cve ac
    WHERE ac.advisory_pk = ap.advisory_pk AND COALESCE(ap.cve_id, '') = ''
) bundle ON true
WHERE p.product_clean = ANY(%(products)s)
"""

ACTION_KINDS = ("verify", "workaround")
ACTIONS_SQL = """
SELECT a.advisory_id, act.kind, act.action_text, act.commands, act.extracted_by,
       (length(btrim(COALESCE(act.evidence_quote, ''))) > 0) AS has_quote
FROM kb.advisory_action act
JOIN kb.advisory a        ON a.advisory_pk = act.advisory_pk AND a.valid_to IS NULL
JOIN kb.load_generation g ON g.gen_id = a.gen_id AND g.is_current
WHERE a.advisory_id = ANY(%(advisories)s)
  AND act.kind = ANY(%(kinds)s)
ORDER BY a.advisory_id, act.kind
"""


class CorpusUnavailable(RuntimeError):
    pass


def connect():
    import psycopg

    conn = psycopg.connect("")
    conn.read_only = True
    with conn.cursor() as cur:
        cur.execute(f"SET statement_timeout = {_STATEMENT_TIMEOUT_MS}")
    return conn


@contextmanager
def _connection(conn) -> Iterator:
    if conn is not None:
        yield conn
        return
    try:
        own = connect()
    except Exception as e:
        raise CorpusUnavailable("advisory corpus unavailable") from e
    try:
        yield own
    finally:
        own.close()


def _plain(v):
    if isinstance(v, decimal.Decimal):
        return float(v)
    if isinstance(v, datetime.date):
        return v.isoformat()
    return v


def _fetch(conn, sql: str, params: dict | None = None) -> list:
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params or {})
            names = [d[0] for d in cur.description]
            rows = cur.fetchall()
            return [{n: _plain(v) for n, v in zip(names, row, strict=True)} for row in rows]
    except Exception as e:
        raise CorpusUnavailable("advisory corpus unavailable") from e


def current_generation(conn=None) -> int:
    with _connection(conn) as c:
        rows = _fetch(c, CURRENT_GENERATION_SQL)
    if len(rows) != 1:
        raise CorpusUnavailable("no current corpus generation")
    return int(rows[0]["gen_id"])


def product_rows(products: list, conn=None) -> list:
    names = [p for p in (products or []) if p]
    if not names:
        raise ValueError("product_rows needs at least one product name")
    with _connection(conn) as c:
        rows = _fetch(c, PRODUCT_ROWS_SQL, {"products": names})
    if not rows:
        raise CorpusUnavailable("advisory corpus holds no rows for this platform")
    return rows


def actions_for(advisory_ids: list, conn=None) -> list:
    ids = sorted({a for a in (advisory_ids or []) if a})
    if not ids:
        return []
    with _connection(conn) as c:
        return _fetch(c, ACTIONS_SQL, {"advisories": ids, "kinds": list(ACTION_KINDS)})
