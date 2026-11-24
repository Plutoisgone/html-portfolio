"""Property-based / fuzz tests (Hypothesis) for code that handles untrusted input
or protects integrity. Real code, no mocks of the logic under test."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from hypothesis import HealthCheck, given, settings, strategies as st
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from siem import audit, checkpoint
from siem.collector import Frames
from siem.event_query import search_query
from siem.events import MAX_FRAME, normalize
from siem.security import RateLimiter, RequestBoundaryMiddleware, SecurityHeadersMiddleware, client_key, csrf_ok
from test_unit import chain

FUZZ = settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])


# ------------------------------------------------------------------ syslog input
@FUZZ
@given(st.lists(st.binary(min_size=0, max_size=4096), max_size=12))
def test_frame_parser_is_bounded_and_fails_closed(chunks):
    f = Frames()
    try:
        for c in chunks:
            for frame in f.feed(c):
                assert 1 <= len(frame) <= MAX_FRAME
        assert len(f.buffer) <= MAX_FRAME + 4096 + 6
    except ValueError:
        pass  # malformed input closes the connection


@FUZZ
@given(st.binary(min_size=1, max_size=MAX_FRAME))
def test_normalize_only_raises_value_error(frame):
    try:
        ev = normalize("fw-1", frame)
    except ValueError:
        return
    assert ev.source == "fw-1"                         # identity never taken from content
    assert not any(ord(c) < 32 and c != "\t" for c in ev.message)
    assert ev.facility is None or 0 <= ev.facility <= 23
    assert ev.severity is None or 0 <= ev.severity <= 7


@FUZZ
@given(st.text(max_size=200), st.text(max_size=200), st.text(max_size=30))
def test_event_search_sql_shape_never_changes(source, term, rule):
    try:
        sql, params = search_query(source, term, rule)
    except ValueError:
        return
    # User input only ever travels as bound parameters: the SQL text depends solely on
    # WHICH filters are present, never on their values.
    canonical, _ = search_query("src" if source else "", "t" if term else "", rule)
    assert sql == canonical
    assert sql.count("%s") == len(params)
    assert sql.startswith("SELECT id, received_at, source_id") and sql.endswith("LIMIT 100")


# ------------------------------------------------------------------ audit integrity
FIELDS = ["id", "actor", "action", "target", "severity", "ip", "user_agent", "details", "ts", "prev_hash", "hash"]


@FUZZ
@given(st.integers(min_value=0, max_value=5), st.sampled_from(FIELDS), st.data())
def test_any_single_field_change_is_detected(index, field, data):
    rows = chain(6)
    head = (6, rows[-1]["hash"])
    r = rows[index]
    if field == "id":
        r["id"] = data.draw(st.integers(min_value=1, max_value=10**9).filter(lambda v: v != r["id"]))
    elif field == "ts":
        r["ts"] = datetime(2027, 1, 1, tzinfo=timezone.utc)
    elif field == "details":
        r["details"] = {"x": data.draw(st.text(max_size=20))}
    elif field == "ip":
        r["ip"] = "198.51.100.9"
    elif field in ("prev_hash", "hash"):
        r[field] = data.draw(st.text("0123456789abcdef", min_size=64, max_size=64).filter(lambda v: v != r[field]))
    else:
        r[field] = data.draw(st.text(min_size=1, max_size=40).filter(lambda v: v != r[field]))
    assert not audit.verify_rows(rows, expected=head)[0]


@FUZZ
@given(st.permutations(list(range(6))))
def test_any_reordering_is_detected(order):
    rows = chain(6)
    head = (6, rows[-1]["hash"])
    shuffled = [rows[i] for i in order]
    assert audit.verify_rows(shuffled, expected=head)[0] == (order == list(range(6)))


@FUZZ
@given(st.integers(min_value=0, max_value=5), st.integers(min_value=1, max_value=6))
def test_any_deletion_or_truncation_is_detected_against_protected_head(start, count):
    rows = chain(6)
    head = (6, rows[-1]["hash"])
    del rows[start:start + count]
    assert not audit.verify_rows(rows, expected=head)[0]


@FUZZ
@given(st.binary(max_size=600))
def test_checkpoint_decode_never_accepts_garbage(blob):
    try:
        checkpoint.decode(b"k" * 32, blob)
    except (ValueError, KeyError, TypeError, AttributeError):
        return
    raise AssertionError("random bytes accepted as an authenticated checkpoint")


@FUZZ
@given(st.integers(min_value=1, max_value=2**40), st.text("0123456789abcdef", min_size=64, max_size=64),
       st.integers(min_value=0, max_value=2**40))
def test_checkpoint_forgery_without_key_rejected(i, h, j):
    good = json.loads(checkpoint.encode(b"k" * 32, i, h))
    good["body"]["id"] = j
    blob = json.dumps(good).encode()
    if j == i:
        assert checkpoint.decode(b"k" * 32, blob) == (i, h)
    else:
        try:
            checkpoint.decode(b"k" * 32, blob)
            raise AssertionError("modified checkpoint accepted")
        except ValueError:
            pass


# ------------------------------------------------------------------ HTTP boundary
def _client():
    async def echo(request):
        return PlainTextResponse(str(len(await request.body())))
    app = Starlette(routes=[Route("/f", echo, methods=["GET", "POST"])])
    return TestClient(SecurityHeadersMiddleware(RequestBoundaryMiddleware(app, "https://siem.test", max_body=512)),
                      raise_server_exceptions=False)


CLIENT = _client()
header_value = st.text(st.characters(min_codepoint=32, max_codepoint=126), max_size=60)


@settings(max_examples=250, deadline=None)
@given(st.sampled_from(["GET", "POST", "HEAD", "PUT", "DELETE"]), st.binary(max_size=2048),
       st.dictionaries(st.sampled_from(["origin", "content-type", "x-a"]), header_value, max_size=3))
def test_request_boundary_never_500_and_always_has_headers(method, body, headers):
    r = CLIENT.request(method, "/f", content=body, headers=headers)
    assert r.status_code < 500
    assert "content-security-policy" in r.headers
    if r.status_code == 200 and method == "POST":
        assert int(r.text) <= 512


@FUZZ
@given(st.text(max_size=120), st.one_of(st.none(), st.text(max_size=120)))
def test_csrf_compare_total_and_exact(expected, provided):
    expected = expected or "x"
    assert csrf_ok(expected, provided) == (provided is not None and provided == expected and len(provided) <= 100)


@FUZZ
@given(st.lists(st.text(max_size=50), min_size=1, max_size=300))
def test_rate_limiter_never_exceeds_cap(keys):
    rl = RateLimiter(5, 60, max_keys=50)
    for n, k in enumerate(keys):
        rl.allow(client_key(k) if n % 2 else k, now=float(n) * 0.01)
        assert len(rl) <= 50
