-- Run as bootstrap superuser only against a disposable Phase 1 lab.
-- This verifies real grants, insert and retention. No production data is changed.
\set ON_ERROR_STOP on
BEGIN;
DO $$
BEGIN
 IF NOT has_column_privilege('siem_ingest','security_events','message','INSERT') OR
    has_any_column_privilege('siem_ingest','security_events','SELECT') OR
    has_column_privilege('siem_ingest','security_events','received_at','INSERT') OR
    has_any_column_privilege('siem_ingest','security_events','UPDATE') OR
    has_table_privilege('siem_ingest','security_events','DELETE') OR
    has_any_column_privilege('siem_ingest','users','SELECT,INSERT,UPDATE') OR
    has_any_column_privilege('siem_ingest','sessions','SELECT,INSERT,UPDATE') OR
    has_any_column_privilege('siem_ingest','audit_log','SELECT,INSERT,UPDATE') OR
    has_function_privilege('siem_ingest','prune_security_events()','EXECUTE') OR
    has_function_privilege('siem_ingest','consume_breakglass(bytea)','EXECUTE') OR
    has_any_column_privilege('siem_app','security_events','INSERT,UPDATE') OR
    has_table_privilege('siem_app','security_events','DELETE') OR
    NOT has_table_privilege('siem_app','security_events','SELECT') OR
    NOT has_function_privilege('siem_worker','prune_security_events()','EXECUTE') THEN
    RAISE EXCEPTION 'Event privilege check failed';
 END IF;
END $$;
SET LOCAL ROLE siem_ingest;
INSERT INTO security_events(source_id,facility,severity,message,rule_id)
VALUES ('acceptance-test',16,4,'action=deny','firewall_deny');
RESET ROLE;
INSERT INTO security_events(source_id,received_at,message)
VALUES ('acceptance-test',now()-interval '25 hours','expired');
SET LOCAL ROLE siem_worker;
SELECT prune_security_events();
RESET ROLE;
SET LOCAL ROLE siem_app;
SELECT count(*)=1 AS event_ok FROM security_events WHERE source_id='acceptance-test' \gset
RESET ROLE;
\if :event_ok
\else
 SELECT 1/0;
\endif
ROLLBACK;
\echo Phase 1 event acceptance checks passed.
