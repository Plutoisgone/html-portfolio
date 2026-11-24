"""PostgreSQL access. All queries are parameterised; never build SQL from input."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from psycopg_pool import ConnectionPool

_pool: ConnectionPool | None = None


def init_pool(dsn: str, min_size: int = 1, max_size: int = 10) -> ConnectionPool:
    from psycopg.rows import dict_row
    from psycopg_pool import ConnectionPool
    global _pool
    _pool = ConnectionPool(
        dsn, min_size=min_size, max_size=max_size, kwargs={"row_factory": dict_row}, open=True
    )
    return _pool


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None


@contextmanager
def tx() -> Iterator[Any]:
    """A connection inside one transaction; commits on success, rolls back on error."""
    if _pool is None:
        raise RuntimeError("Database pool not initialised")
    with _pool.connection() as conn:
        with conn.transaction():
            yield conn


def fetch_one(sql: str, params: tuple | dict = ()) -> dict | None:
    with tx() as conn:
        return conn.execute(sql, params).fetchone()


def fetch_all(sql: str, params: tuple | dict = ()) -> list[dict]:
    with tx() as conn:
        return conn.execute(sql, params).fetchall()


def execute(sql: str, params: tuple | dict = ()) -> None:
    with tx() as conn:
        conn.execute(sql, params)
