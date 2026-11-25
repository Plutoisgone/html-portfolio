-- LIVE acceptance test. Run ONLY on a disposable lab, as the local bootstrap superuser:
--   docker compose exec -T postgres psql -U siem_bootstrap -d siem -v ON_ERROR_STOP=1 < app/tests/db_acceptance.sql
-- Default role names from .env.example. Everything runs in one transaction and is rolled back.
\set ON_ERROR_STOP on
BEGIN;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('siem_owner','siem_app','siem_worker','siem_emergency','siem_ingest','siem_auth')
             AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)) OR
     has_table_privilege('siem_worker','users','SELECT') OR
     has_table_privilege('siem_worker','sessions','DELETE') OR
     has_table_privilege('siem_worker','audit_log','INSERT') OR
     has_table_privilege('siem_app','audit_head','UPDATE') OR
     has_table_privilege('siem_app','audit_log','UPDATE') OR
     has_table_privilege('siem_app','audit_log','DELETE') OR
     has_table_privilege('siem_app','audit_log','TRUNCATE') OR
     has_column_privilege('siem_app','audit_log','txid','INSERT') OR
     has_table_privilege('siem_app','breakglass_tokens','INSERT') OR
     has_table_privilege('siem_app','users','INSERT') OR
     has_column_privilege('siem_app','users','role','UPDATE') OR
     has_column_privilege('siem_app','users','active','UPDATE') OR
     has_column_privilege('siem_app','users','entra_oid','UPDATE') OR
     has_table_privilege('siem_app','audit_verification','INSERT') OR
     has_function_privilege('siem_app','admin_actor(text,integer)','EXECUTE') OR
     has_table_privilege('siem_emergency','users','UPDATE') OR
     has_column_privilege('siem_emergency','users','entra_oid','SELECT') OR
     has_column_privilege('siem_emergency','breakglass_tokens','used_at','INSERT') OR
     has_column_privilege('siem_worker','audit_verification','checked_at','INSERT') OR
     NOT has_function_privilege('siem_worker','cleanup_expired()','EXECUTE') OR
     -- N12: only the login-service role may create sessions or call the sign-in functions.
     has_table_privilege('siem_app','sessions','INSERT') OR
     has_function_privilege('siem_app','consume_breakglass(bytea)','EXECUTE') OR
     has_function_privilege('siem_app','bootstrap_first_admin(uuid,text)','EXECUTE') OR
     NOT has_table_privilege('siem_app','sessions','SELECT') OR
     NOT has_table_privilege('siem_app','sessions','DELETE') OR
     NOT has_column_privilege('siem_app','sessions','last_seen_at','UPDATE') OR
     NOT has_function_privilege('siem_auth','consume_breakglass(bytea)','EXECUTE') OR
     NOT has_function_privilege('siem_auth','bootstrap_first_admin(uuid,text)','EXECUTE') OR
     NOT has_table_privilege('siem_auth','sessions','SELECT') OR
     NOT has_table_privilege('siem_auth','sessions','INSERT') OR
     NOT has_table_privilege('siem_auth','sessions','DELETE') OR
     has_table_privilege('siem_auth','sessions','UPDATE') OR
     has_column_privilege('siem_auth','sessions','last_seen_at','UPDATE') OR
     has_table_privilege('siem_auth','users','INSERT') OR
     has_table_privilege('siem_auth','users','DELETE') OR
     has_column_privilege('siem_auth','users','role','UPDATE') OR
     has_column_privilege('siem_auth','users','active','UPDATE') OR
     NOT has_column_privilege('siem_auth','users','last_login_at','UPDATE') OR
     has_table_privilege('siem_auth','breakglass_tokens','SELECT') OR
     has_table_privilege('siem_auth','audit_log','UPDATE') OR
     has_table_privilege('siem_auth','audit_head','UPDATE') OR
     has_column_privilege('siem_auth','audit_log','txid','INSERT') OR
     has_table_privilege('siem_auth','security_events','SELECT') OR
     has_table_privilege('siem_auth','audit_verification','SELECT') OR
     has_function_privilege('siem_auth','admin_actor(text,integer)','EXECUTE') OR
     has_function_privilege('siem_auth','admin_set_role(text,integer,integer,text)','EXECUTE') OR
     has_function_privilege('siem_auth','session_customer_ids(text,integer)','EXECUTE') OR
     has_table_privilege('siem_auth','customers','SELECT') OR
     has_table_privilege('siem_auth','staff_customers','SELECT') OR
     NOT has_function_privilege('siem_app','admin_set_role(text,integer,integer,text)','EXECUTE') THEN
    RAISE EXCEPTION 'Privilege acceptance test failed';
  END IF;
END $$;

INSERT INTO users(email,entra_oid,role) VALUES ('regression-test@invalid.test','e2f20e4b-e82b-4d6d-94cf-9c483d4caecb','super_admin') RETURNING id AS test_uid \gset
-- (the deferred audit trigger fires at COMMIT; this transaction is rolled back)
INSERT INTO breakglass_tokens(token_hash,user_id,expires_at) VALUES (decode(repeat('a1',32),'hex'),:test_uid,now()+interval '5 minutes');
-- N12 (Phase 1 review): the web role must not be able to create a session at all,
-- neither by INSERT nor through the sign-in functions. A stolen web-app DB password
-- used to be enough to insert a 'sso' super-admin session row.
SET LOCAL ROLE siem_app;
DO $$
BEGIN
  BEGIN
    INSERT INTO sessions(id_hash,user_id,csrf_token,via,expires_at)
    SELECT decode(repeat('b1',32),'hex'), id, repeat('c',43), 'sso', now()+interval '1 hour'
      FROM users WHERE email='regression-test@invalid.test';
    RAISE EXCEPTION 'N12: web role inserted a session row';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    PERFORM * FROM bootstrap_first_admin('e2f20e4b-e82b-4d6d-94cf-000000000001','x@invalid.test');
    RAISE EXCEPTION 'N12: web role may call bootstrap_first_admin';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    PERFORM * FROM consume_breakglass(decode(repeat('a1',32),'hex'));
    RAISE EXCEPTION 'N12: web role may call consume_breakglass';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END $$;
RESET ROLE;
-- The login-service role cannot change roles, and sees no customer data at all
-- (no privilege on the tenancy tables, so not even RLS-filtered rows).
SET LOCAL ROLE siem_auth;
DO $$
BEGIN
  BEGIN
    UPDATE users SET role='super_admin' WHERE email='regression-test@invalid.test';
    RAISE EXCEPTION 'N12: login-service role changed a role';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    PERFORM set_config('siem.session', repeat('x',43), true);
    PERFORM count(*) FROM customers;
    RAISE EXCEPTION 'N12: login-service role can read customers';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    PERFORM count(*) FROM staff_customers;
    RAISE EXCEPTION 'N12: login-service role can read staff_customers';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END $$;
SELECT count(*)=1 AS first_ok FROM consume_breakglass(decode(repeat('a1',32),'hex')) \gset
SELECT count(*)=0 AS replay_ok FROM consume_breakglass(decode(repeat('a1',32),'hex')) \gset
RESET ROLE;

-- Demotion revokes outstanding break-glass tokens (trigger), whoever performs it.
INSERT INTO breakglass_tokens(token_hash,user_id,expires_at) VALUES (decode(repeat('a2',32),'hex'),:test_uid,now()+interval '5 minutes');
UPDATE users SET role='analyst' WHERE id=:test_uid;
SET LOCAL ROLE siem_auth;
SELECT count(*)=0 AS demoted_ok FROM consume_breakglass(decode(repeat('a2',32),'hex')) \gset
RESET ROLE;
SET LOCAL ROLE siem_app;
-- The web role cannot change roles directly any more (Phase 0.1).
SAVEPOINT direct;
\set ON_ERROR_STOP off
UPDATE users SET role='super_admin' WHERE id=:test_uid;
\set ON_ERROR_STOP on
ROLLBACK TO SAVEPOINT direct;
SELECT role='analyst' AS direct_blocked FROM users WHERE id=:test_uid \gset
-- ...nor through the admin function without a live super-admin session token.
SAVEPOINT fn;
\set ON_ERROR_STOP off
SELECT * FROM admin_set_role(repeat('x',43), 30, :test_uid, 'super_admin');
\set ON_ERROR_STOP on
ROLLBACK TO SAVEPOINT fn;
SELECT role='analyst' AS fn_blocked FROM users WHERE id=:test_uid \gset
RESET ROLE;

\if :first_ok
\else
  SELECT 1/0;
\endif
\if :replay_ok
\else
  SELECT 1/0;
\endif
\if :demoted_ok
\else
  SELECT 1/0;
\endif
\if :direct_blocked
\else
  SELECT 1/0;
\endif
\if :fn_blocked
\else
  SELECT 1/0;
\endif
ROLLBACK;

-- A privileged change WITHOUT an audit record must fail at COMMIT.
BEGIN;
INSERT INTO users(email,entra_oid,role) VALUES ('no-audit@invalid.test','b0b0b0b0-0000-4000-8000-000000000001','super_admin');
\set ON_ERROR_STOP off
COMMIT;
\set ON_ERROR_STOP on
SELECT count(*)=0 AS unaudited_rejected FROM users WHERE email='no-audit@invalid.test' \gset
\if :unaudited_rejected
\else
  SELECT 1/0;
\endif
\echo Database privilege, token and audit-enforcement acceptance checks passed.
