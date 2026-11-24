-- LIVE acceptance test for customer separation (migration 6). Run ONLY on a
-- disposable lab, as the local bootstrap superuser:
--   docker compose exec -T postgres psql -U siem_bootstrap -d siem -v ON_ERROR_STOP=1 < app/tests/db_tenancy_acceptance.sql
-- Default role names from .env.example. Everything runs in one transaction and is rolled back.
\set ON_ERROR_STOP on
BEGIN;

-- Grants: the web role may only read (through RLS) and call the definer functions.
DO $$
BEGIN
  IF has_table_privilege('siem_app','customers','INSERT') OR
     has_table_privilege('siem_app','customers','UPDATE') OR
     has_table_privilege('siem_app','customers','DELETE') OR
     has_table_privilege('siem_app','customers','TRUNCATE') OR
     has_table_privilege('siem_app','staff_customers','INSERT') OR
     has_table_privilege('siem_app','staff_customers','UPDATE') OR
     has_table_privilege('siem_app','staff_customers','DELETE') OR
     has_table_privilege('siem_app','staff_customers','TRUNCATE') OR
     NOT has_table_privilege('siem_app','customers','SELECT') OR
     NOT has_table_privilege('siem_app','staff_customers','SELECT') OR
     has_any_column_privilege('siem_worker','customers','SELECT,INSERT,UPDATE') OR
     has_any_column_privilege('siem_emergency','customers','SELECT,INSERT,UPDATE') OR
     has_any_column_privilege('siem_ingest','customers','SELECT,INSERT,UPDATE') OR
     has_any_column_privilege('siem_worker','staff_customers','SELECT,INSERT,UPDATE') OR
     has_any_column_privilege('siem_emergency','staff_customers','SELECT,INSERT,UPDATE') OR
     has_any_column_privilege('siem_ingest','staff_customers','SELECT,INSERT,UPDATE') OR
     has_function_privilege('siem_worker','session_customer_ids(text,integer)','EXECUTE') OR
     has_function_privilege('siem_ingest','session_customer_ids(text,integer)','EXECUTE') OR
     has_function_privilege('siem_emergency','admin_create_customer(text,integer,text,text)','EXECUTE') OR
     has_function_privilege('siem_app','require_tenant_audit()','EXECUTE') OR
     NOT has_function_privilege('siem_app','session_customer_ids(text,integer)','EXECUTE') OR
     NOT has_function_privilege('siem_app','admin_create_customer(text,integer,text,text)','EXECUTE') OR
     NOT has_function_privilege('siem_app','admin_set_customer_active(text,integer,integer,boolean)','EXECUTE') OR
     NOT has_function_privilege('siem_app','admin_assign_staff(text,integer,integer,integer,boolean)','EXECUTE') OR
     NOT (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid='public.customers'::regclass) OR
     NOT (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid='public.staff_customers'::regclass) THEN
    RAISE EXCEPTION 'Tenancy privilege acceptance test failed';
  END IF;
END $$;

-- Fixtures (as bootstrap superuser; deferred user audit triggers never fire, we roll back).
INSERT INTO users(email,entra_oid,role) VALUES
  ('tenancy-admin@invalid.test','7a3c1f20-0000-4000-8000-000000000001','super_admin'),
  ('tenancy-analyst@invalid.test','7a3c1f20-0000-4000-8000-000000000002','analyst');
SELECT id AS admin_uid FROM users WHERE email='tenancy-admin@invalid.test' \gset
SELECT id AS analyst_uid FROM users WHERE email='tenancy-analyst@invalid.test' \gset
\set admin_tok 'tenancy-admin-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
\set analyst_tok 'tenancy-analyst-token-bbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
\set bg_tok 'tenancy-breakglass-token-ccccccccccccccccccccccccc'
INSERT INTO sessions(id_hash,user_id,csrf_token,via,expires_at) VALUES
  (sha256(convert_to(:'admin_tok','UTF8')),:admin_uid,repeat('c',43),'sso',now()+interval '1 hour'),
  (sha256(convert_to(:'analyst_tok','UTF8')),:analyst_uid,repeat('c',43),'sso',now()+interval '1 hour'),
  (sha256(convert_to(:'bg_tok','UTF8')),:admin_uid,repeat('c',43),'breakglass',now()+interval '1 hour');

-- Block 1: the web role cannot write the tables directly.
SET LOCAL ROLE siem_app;
DO $$
BEGIN
  BEGIN
    INSERT INTO customers(slug,name) VALUES ('direct-insert','Direct');
    RAISE EXCEPTION 'direct INSERT INTO customers was allowed';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    UPDATE customers SET active=false;
    RAISE EXCEPTION 'direct UPDATE customers was allowed';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    INSERT INTO staff_customers(user_id,customer_id) VALUES (1,1);
    RAISE EXCEPTION 'direct INSERT INTO staff_customers was allowed';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END $$;

-- Block 2: input validation, uniqueness and audit enforcement on admin_create_customer.
SELECT set_config('tenancy.admin_tok', :'admin_tok', true);
SELECT set_config('tenancy.analyst_tok', :'analyst_tok', true);
DO $$
DECLARE tok text := current_setting('tenancy.admin_tok'); bad text;
BEGIN
  FOREACH bad IN ARRAY ARRAY['Bad Slug','a',repeat('b',33),'-leading','UPPER'] LOOP
    BEGIN
      PERFORM admin_create_customer(tok, 30, bad, 'Name');
      RAISE EXCEPTION 'invalid slug % was accepted', bad;
    EXCEPTION WHEN check_violation THEN NULL;
    END;
  END LOOP;
  BEGIN
    PERFORM admin_create_customer(tok, 30, 'valid-slug', E'Bad\nName');
    RAISE EXCEPTION 'name with control character was accepted';
  EXCEPTION WHEN check_violation THEN NULL;
  END;
  BEGIN
    PERFORM admin_create_customer(tok, 30, 'valid-slug', '');
    RAISE EXCEPTION 'empty name was accepted';
  EXCEPTION WHEN check_violation THEN NULL;
  END;
  BEGIN
    PERFORM admin_create_customer(tok, 30, 'dup-slug', 'First');
    PERFORM admin_create_customer(tok, 30, 'dup-slug', 'Second');
    RAISE EXCEPTION 'duplicate slug was accepted';
  EXCEPTION WHEN unique_violation THEN NULL;
  END;
  -- An unknown or wrong-format token is refused.
  BEGIN
    PERFORM admin_create_customer(repeat('x',43), 30, 'no-token', 'No token');
    RAISE EXCEPTION 'unknown token created a customer';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END $$;

-- A customer created without an audit record in the same transaction cannot commit.
RESET ROLE;
DO $$
BEGIN
  BEGIN
    PERFORM admin_create_customer(current_setting('tenancy.admin_tok'), 30, 'unaudited-2', 'Unaudited');
    SET CONSTRAINTS customers_require_audit IMMEDIATE;
    RAISE EXCEPTION 'unaudited customer passed the audit check';
  EXCEPTION WHEN SQLSTATE 'SIA01' THEN NULL;
  END;
END $$;
SET CONSTRAINTS customers_require_audit DEFERRED;

-- audited_step(call, trigger, target slug, good action, wrong action) runs one privileged call
-- four times against the named deferred audit trigger:
--   no audit row -> SIA01; wrong action -> SIA01; right action, wrong target -> SIA01;
--   right action and target -> passes (and only this run's change is kept).
-- Each failing run is inside its own subtransaction, so its change is undone.
-- Note: the trigger accepts any audit row of the current transaction, so each
-- (action, slug) pair can only be probed the first time it occurs in this test.
CREATE PROCEDURE pg_temp.audited_step(p_call text, p_trg text, p_target text, p_good text,
                                      p_bad text, INOUT r text DEFAULT NULL)
LANGUAGE plpgsql AS $f$
DECLARE probe record;
BEGIN
  FOR probe IN SELECT * FROM (VALUES (1, NULL::text, NULL::text), (2, p_bad, NULL), (3, p_good, 'not-this-slug')) v(n, act, tgt) LOOP
    BEGIN
      EXECUTE p_call INTO r;
      IF probe.act IS NOT NULL THEN
        INSERT INTO audit_log(id,actor,action,target,severity,prev_hash,hash)
          SELECT last_id+1,'tenancy-admin@invalid.test',probe.act,coalesce(probe.tgt, p_target),'info',last_hash,repeat('e',64) FROM audit_head;
      END IF;
      EXECUTE format('SET CONSTRAINTS %I IMMEDIATE', p_trg);
      RAISE EXCEPTION 'audit check % for [%] passed without a matching audit row', probe.n, p_call;
    EXCEPTION WHEN SQLSTATE 'SIA01' THEN NULL;
    END;
    EXECUTE format('SET CONSTRAINTS %I DEFERRED', p_trg);
  END LOOP;
  EXECUTE p_call INTO r;
  INSERT INTO audit_log(id,actor,action,target,severity,prev_hash,hash)
    SELECT last_id+1,'tenancy-admin@invalid.test',p_good,p_target,'info',last_hash,repeat('f',64) FROM audit_head;
  EXECUTE format('SET CONSTRAINTS %I IMMEDIATE', p_trg);
  EXECUTE format('SET CONSTRAINTS %I DEFERRED', p_trg);
END $f$;

-- With a matching audit record (written by the caller, like the web app does), it passes.
CALL pg_temp.audited_step(format('SELECT admin_create_customer(%L, 30, %L, %L)', :'admin_tok', 'cust-a', 'Customer A'),
  'customers_require_audit', 'cust-a', 'customer.created', 'customer.activated') \gset step_
SELECT :'step_r' IS NOT NULL AS create_a_audited \gset
CALL pg_temp.audited_step(format('SELECT admin_create_customer(%L, 30, %L, %L)', :'admin_tok', 'cust-b', 'Customer B'),
  'customers_require_audit', 'cust-b', 'customer.created', 'customer.staff_assigned') \gset step_
SELECT :'step_r' IS NOT NULL AS create_b_audited \gset
SELECT id AS cust_a FROM customers WHERE slug='cust-a' \gset
SELECT id AS cust_b FROM customers WHERE slug='cust-b' \gset

-- Staff assignment requires its own audit record too.
CALL pg_temp.audited_step(format('SELECT admin_assign_staff(%L, 30, %s, %s, true)', :'admin_tok', :analyst_uid, :cust_a),
  'staff_customers_require_audit', 'cust-a', 'customer.staff_assigned', 'customer.staff_removed') \gset step_
SELECT :'step_r' = 'cust-a' AS assign_ok \gset
SET LOCAL ROLE siem_app;

-- Block 3: session-bound scope.
SELECT session_customer_ids(:'analyst_tok', 30) = ARRAY[:cust_a]::integer[] AS analyst_scope_ok \gset
SELECT session_customer_ids(:'admin_tok', 30) @> ARRAY[:cust_a, :cust_b]::integer[] AS admin_scope_ok \gset
SELECT session_customer_ids(:'bg_tok', 30) = '{}'::integer[] AS breakglass_scope_ok \gset
SELECT session_customer_ids(repeat('r',40), 30) = '{}'::integer[] AS random_scope_ok \gset
SELECT session_customer_ids(NULL, 30) = '{}'::integer[] AND session_customer_ids('', 30) = '{}'::integer[]
   AND session_customer_ids(:'analyst_tok', 0) = '{}'::integer[] AS degenerate_scope_ok \gset
SELECT count(*)=0 AS unset_rls_ok FROM customers \gset
SELECT count(*)=0 AS unset_staff_rls_ok FROM staff_customers \gset
SET LOCAL siem.session = :'analyst_tok';
SELECT count(*)=1 AS analyst_rls_ok FROM customers \gset
SELECT count(*)=1 AS analyst_rls_slug_ok FROM customers WHERE slug='cust-a' \gset
SELECT count(*)=1 AS analyst_staff_rls_ok FROM staff_customers \gset
SET LOCAL siem.session = :'admin_tok';
RESET ROLE;
SELECT count(*) AS active_total FROM customers WHERE active \gset
SET LOCAL ROLE siem_app;
SELECT count(*)=:active_total AS admin_rls_ok FROM customers \gset
SELECT array_length(session_customer_ids(:'admin_tok', 30), 1) = :active_total AS admin_all_active_ok \gset
SET LOCAL siem.session = :'bg_tok';
SELECT count(*)=0 AS breakglass_rls_ok FROM customers \gset
SET LOCAL siem.session = '';
-- The scope check must not refresh the session's idle timer.
RESET ROLE;
UPDATE sessions SET last_seen_at = now() - interval '10 minutes' WHERE id_hash = sha256(convert_to(:'analyst_tok','UTF8'));
SET LOCAL ROLE siem_app;
SELECT session_customer_ids(:'analyst_tok', 5) = '{}'::integer[] AS idle_scope_ok \gset
SELECT session_customer_ids(:'analyst_tok', 30) = ARRAY[:cust_a]::integer[] AS idle_ok_scope_ok \gset
RESET ROLE;
SELECT last_seen_at < now() - interval '9 minutes' AS last_seen_untouched FROM sessions
 WHERE id_hash = sha256(convert_to(:'analyst_tok','UTF8')) \gset
UPDATE sessions SET expires_at = now() - interval '1 second', created_at = now() - interval '1 hour'
 WHERE id_hash = sha256(convert_to(:'analyst_tok','UTF8'));
SET LOCAL ROLE siem_app;
SELECT session_customer_ids(:'analyst_tok', 30) = '{}'::integer[] AS expired_scope_ok \gset
RESET ROLE;
UPDATE sessions SET expires_at = now() + interval '1 hour', last_seen_at = now()
 WHERE id_hash = sha256(convert_to(:'analyst_tok','UTF8'));
SET LOCAL ROLE siem_app;

-- Block 4: deactivation, unassignment and user deactivation all remove scope; every
-- one of these changes is refused at COMMIT without its exact audit record.
RESET ROLE;
CALL pg_temp.audited_step(format('SELECT admin_set_customer_active(%L, 30, %s, false)', :'admin_tok', :cust_a),
  'customers_require_audit', 'cust-a', 'customer.deactivated', 'customer.activated') \gset step_
SELECT :'step_r' = 'cust-a' AS deact_ok \gset
SET LOCAL ROLE siem_app;
SELECT session_customer_ids(:'analyst_tok', 30) = '{}'::integer[] AS deact_scope_ok \gset
SELECT NOT (session_customer_ids(:'admin_tok', 30) @> ARRAY[:cust_a]::integer[]) AS admin_deact_scope_ok \gset
RESET ROLE;
CALL pg_temp.audited_step(format('SELECT admin_set_customer_active(%L, 30, %s, true)', :'admin_tok', :cust_a),
  'customers_require_audit', 'cust-a', 'customer.activated', 'customer.deactivated') \gset step_
SELECT :'step_r' = 'cust-a' AS react_ok \gset
SET LOCAL ROLE siem_app;
SELECT session_customer_ids(:'analyst_tok', 30) = ARRAY[:cust_a]::integer[] AS react_scope_ok \gset
RESET ROLE;
CALL pg_temp.audited_step(format('SELECT admin_assign_staff(%L, 30, %s, %s, false)', :'admin_tok', :analyst_uid, :cust_a),
  'staff_customers_require_audit', 'cust-a', 'customer.staff_removed', 'customer.staff_assigned') \gset step_
SELECT :'step_r' = 'cust-a' AS unassign_ok \gset
SET LOCAL ROLE siem_app;
SELECT session_customer_ids(:'analyst_tok', 30) = '{}'::integer[] AS unassign_scope_ok \gset
RESET ROLE;
-- (re-assignment: the earlier customer.staff_assigned/cust-a row of this transaction
-- already satisfies the trigger, so it is not probed again here)
SELECT admin_assign_staff(:'admin_tok', 30, :analyst_uid, :cust_a, true) = 'cust-a' AS reassign_ok \gset
SET LOCAL ROLE siem_app;
SELECT session_customer_ids(:'analyst_tok', 30) = ARRAY[:cust_a]::integer[] AS reassign_scope_ok \gset
RESET ROLE;
-- Deactivating the user (revoke trigger also drops sessions) leaves no scope; also
-- check the scope function itself honours users.active by re-adding the session.
UPDATE users SET active=false WHERE id=:analyst_uid;
INSERT INTO sessions(id_hash,user_id,csrf_token,via,expires_at) VALUES
  (sha256(convert_to(:'analyst_tok','UTF8')),:analyst_uid,repeat('c',43),'sso',now()+interval '1 hour')
  ON CONFLICT DO NOTHING;
SET LOCAL ROLE siem_app;
SELECT session_customer_ids(:'analyst_tok', 30) = '{}'::integer[] AS inactive_user_scope_ok \gset

-- Block 5: non-super-admins cannot manage customers or assignments.
DO $$
DECLARE tok text := current_setting('tenancy.analyst_tok');
BEGIN
  BEGIN
    PERFORM admin_create_customer(tok, 30, 'by-analyst', 'By analyst');
    RAISE EXCEPTION 'analyst created a customer';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    PERFORM admin_assign_staff(tok, 30, 1, 1, true);
    RAISE EXCEPTION 'analyst assigned staff';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    PERFORM admin_set_customer_active(tok, 30, 1, false);
    RAISE EXCEPTION 'analyst changed a customer';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END $$;
RESET ROLE;

\if :create_a_audited
\else
  SELECT 1/0;
\endif
\if :create_b_audited
\else
  SELECT 1/0;
\endif
\if :assign_ok
\else
  SELECT 1/0;
\endif
\if :analyst_scope_ok
\else
  SELECT 1/0;
\endif
\if :admin_scope_ok
\else
  SELECT 1/0;
\endif
\if :breakglass_scope_ok
\else
  SELECT 1/0;
\endif
\if :random_scope_ok
\else
  SELECT 1/0;
\endif
\if :degenerate_scope_ok
\else
  SELECT 1/0;
\endif
\if :unset_rls_ok
\else
  SELECT 1/0;
\endif
\if :unset_staff_rls_ok
\else
  SELECT 1/0;
\endif
\if :analyst_rls_ok
\else
  SELECT 1/0;
\endif
\if :analyst_rls_slug_ok
\else
  SELECT 1/0;
\endif
\if :analyst_staff_rls_ok
\else
  SELECT 1/0;
\endif
\if :admin_rls_ok
\else
  SELECT 1/0;
\endif
\if :admin_all_active_ok
\else
  SELECT 1/0;
\endif
\if :breakglass_rls_ok
\else
  SELECT 1/0;
\endif
\if :idle_scope_ok
\else
  SELECT 1/0;
\endif
\if :idle_ok_scope_ok
\else
  SELECT 1/0;
\endif
\if :last_seen_untouched
\else
  SELECT 1/0;
\endif
\if :expired_scope_ok
\else
  SELECT 1/0;
\endif
\if :deact_ok
\else
  SELECT 1/0;
\endif
\if :deact_scope_ok
\else
  SELECT 1/0;
\endif
\if :admin_deact_scope_ok
\else
  SELECT 1/0;
\endif
\if :react_ok
\else
  SELECT 1/0;
\endif
\if :react_scope_ok
\else
  SELECT 1/0;
\endif
\if :unassign_ok
\else
  SELECT 1/0;
\endif
\if :unassign_scope_ok
\else
  SELECT 1/0;
\endif
\if :reassign_ok
\else
  SELECT 1/0;
\endif
\if :reassign_scope_ok
\else
  SELECT 1/0;
\endif
\if :inactive_user_scope_ok
\else
  SELECT 1/0;
\endif
ROLLBACK;
\echo Tenancy (customers, staff assignment, scope and RLS) acceptance checks passed.
