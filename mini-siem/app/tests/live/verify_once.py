# Piped into the worker container by the live tests (stdin; the rootfs is read-only).
# Runs the worker's own integrity/export path once, using the worker's own credentials.
import sys

from siem import checkpoint, db, worker
from siem.config import Settings, db_dsn, env, secret

key = bytes.fromhex(secret("audit_checkpoint_key"))
s = Settings(hostname="", oidc_tenant_id="", oidc_client_id="", oidc_client_secret="",
             initial_super_admins=[], session_secret="",
             db_dsn=db_dsn("SIEM_DB_WORKER_USER", "db_worker_password"),
             s3_endpoint=env("SIEM_S3_ENDPOINT"), s3_bucket=env("SIEM_S3_BUCKET"),
             s3_region=env("SIEM_S3_REGION"),
             s3_access_key=secret("s3_access_key", required=False),
             s3_secret_key=secret("s3_secret_key", required=False))
db.init_pool(s.db_dsn, min_size=1, max_size=1)
print("checkpoint before:", checkpoint.read(worker.CHECKPOINT_PATH, key))
try:
    n = worker.export_audit(s, key)
    print("RESULT OK exported", n)
except Exception as e:  # report, do not hide
    print("RESULT DETECTED", type(e).__name__, e)
print("checkpoint after:", checkpoint.read(worker.CHECKPOINT_PATH, key))
sys.stdout.flush()
