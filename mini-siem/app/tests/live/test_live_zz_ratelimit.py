"""LIVE: rate limiting. Kept in its own file so it runs last (it exhausts the auth limit)."""
import pytest

from .test_live_http import HEADERS

pytestmark = pytest.mark.live


def test_security_headers_on_rate_limited_response(lab):
    c = lab.http()
    statuses = [c.post("/auth/breakglass", data={"token": "x" * 10}).status_code for _ in range(25)]
    assert 429 in statuses, statuses
    r = c.post("/auth/breakglass", data={"token": "x"})
    assert r.status_code == 429
    assert not [h for h in HEADERS if h not in r.headers]
