"""Load profile for the Phase 0.1 console (run with Locust, see TEST_RESULTS.md).

SIEM_LOAD_COOKIES: comma-separated session tokens (one per simulated admin).
Run against a LAB stack only. All load comes from one source IP, so the per-IP
limiter (300 req/min general, 20 req/min /auth) caps throughput by design; the
flood profile measures that the service stays healthy and bounded while it does.
"""
import itertools
import os

from locust import HttpUser, between, task

TOKENS = itertools.cycle([t for t in os.environ.get("SIEM_LOAD_COOKIES", "").split(",") if t])


class Analyst(HttpUser):
    wait_time = between(2, 4)

    def on_start(self):
        token = next(TOKENS, None)
        if token:
            self.client.cookies.set("__Host-siem", token)
        self.client.verify = os.environ.get("SIEM_LOAD_CA", True)

    @task(5)
    def dashboard(self):
        self.client.get("/", name="/ (dashboard)")

    @task(3)
    def events(self):
        self.client.get("/events?term=deny", name="/events?term")

    @task(2)
    def users(self):
        self.client.get("/admin/users")

    @task(1)
    def audit(self):
        self.client.get("/admin/audit")

    @task(1)
    def login_page(self):
        self.client.get("/login")


class Flood(HttpUser):
    """Unauthenticated hammering of the cheapest and the most expensive public paths."""
    wait_time = between(0, 0.05)

    def on_start(self):
        self.client.verify = os.environ.get("SIEM_LOAD_CA", True)

    @task(3)
    def login(self):
        self.client.get("/login")

    @task(1)
    def breakglass(self):
        self.client.post("/auth/breakglass", data={"token": "x" * 43},
                         headers={"Origin": self.host})
