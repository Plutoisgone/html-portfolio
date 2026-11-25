"""Database schema. Run once per deploy by the one-shot `migrate` service,
connected as the schema owner. The app itself connects as a restricted role
that cannot alter tables, and cannot UPDATE or DELETE audit rows.

Usage: python -m siem.migrate
"""
from __future__ import annotations

import sys

import psycopg
from psycopg import sql as pgsql

from .config import db_dsn, env

MIGRATIONS: list[str] = [
    # 1: core schema
    """
    CREATE TABLE tenants (
        id          serial PRIMARY KEY,
        name        text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 100),
        created_at  timestamptz NOT NULL DEFAULT now()
    );

    CREATE TABLE users (
        id            serial PRIMARY KEY,
        email         text NOT NULL UNIQUE CHECK (email = lower(email) AND length(email) <= 254),
        entra_oid     uuid NOT NULL UNIQUE,
        role          text NOT NULL CHECK (role IN ('super_admin','client_admin','analyst','read_only')),
        active        boolean NOT NULL DEFAULT true,
        created_at    timestamptz NOT NULL DEFAULT now(),
        last_login_at timestamptz
    );

    CREATE TABLE user_tenants (
        user_id   integer NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        tenant_id integer NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        PRIMARY KEY (user_id, tenant_id)
    );

    CREATE TABLE sessions (
        id_hash      bytea PRIMARY KEY,
        user_id      integer NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        csrf_token   text NOT NULL,
        via          text NOT NULL CHECK (via IN ('sso','breakglass')),
        ip           inet,
        user_agent   text,
        created_at   timestamptz NOT NULL DEFAULT now(),
        last_seen_at timestamptz NOT NULL DEFAULT now(),
        expires_at   timestamptz NOT NULL
    );
    CREATE INDEX sessions_user_idx ON sessions(user_id);
    CREATE INDEX sessions_expires_idx ON sessions(expires_at);

    CREATE TABLE breakglass_tokens (
        token_hash  bytea PRIMARY KEY,
        user_id     integer NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at  timestamptz NOT NULL DEFAULT now(),
        expires_at  timestamptz NOT NULL,
        used_at     timestamptz
    );

    CREATE TABLE audit_log (
        id          bigint PRIMARY KEY CHECK (id > 0),
        ts          timestamptz NOT NULL DEFAULT clock_timestamp(),
        actor       text NOT NULL,
        action      text NOT NULL,
        target      text,
        severity    text NOT NULL CHECK (severity IN ('info','warning','critical')),
        ip          inet,
        user_agent  text,
        details     jsonb NOT NULL DEFAULT '{}'::jsonb,
        prev_hash   text NOT NULL,
        hash        text NOT NULL
    );
    CREATE INDEX audit_ts_idx ON audit_log(ts);

    -- Audit rows can never be changed or removed, not even by the table owner
    -- without first dropping this trigger, which the app role cannot do.
    CREATE FUNCTION audit_log_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        RAISE EXCEPTION 'audit_log is append-only';
    END $$;
    CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_log
        FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();

    CREATE TABLE audit_head (
        id integer PRIMARY KEY CHECK (id=1),
        last_id bigint NOT NULL,
        last_hash text NOT NULL
    );
    INSERT INTO audit_head VALUES (1,0,repeat('0',64));
    CREATE FUNCTION advance_audit_head() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    BEGIN
        UPDATE public.audit_head SET last_id=NEW.id,last_hash=NEW.hash
        WHERE id=1 AND last_id=NEW.id-1 AND last_hash=NEW.prev_hash;
        IF NOT FOUND THEN RAISE EXCEPTION 'audit chain sequence mismatch'; END IF;
        RETURN NEW;
    END $$;
    CREATE TRIGGER audit_advance AFTER INSERT ON audit_log
        FOR EACH ROW EXECUTE FUNCTION advance_audit_head();
    CREATE FUNCTION revoke_user_access() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    BEGIN
        IF OLD.role IS DISTINCT FROM NEW.role OR OLD.active IS DISTINCT FROM NEW.active THEN
            DELETE FROM public.sessions WHERE user_id=NEW.id;
            DELETE FROM public.breakglass_tokens WHERE user_id=NEW.id;
        END IF;
        RETURN NEW;
    END $$;
    CREATE TRIGGER revoke_user_access_on_change AFTER UPDATE OF role,active ON users
        FOR EACH ROW EXECUTE FUNCTION revoke_user_access();
    CREATE FUNCTION consume_breakglass(p_hash bytea) RETURNS TABLE(id integer,email text)
    LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
        UPDATE public.breakglass_tokens t SET used_at=now()
        FROM public.users u WHERE t.user_id=u.id AND t.token_hash=p_hash
        AND t.used_at IS NULL AND t.expires_at>now() AND u.active AND u.role='super_admin'
        RETURNING u.id,u.email;
    $$;
    CREATE FUNCTION cleanup_expired() RETURNS void LANGUAGE sql SECURITY DEFINER
    SET search_path=pg_catalog,public AS $$
        DELETE FROM public.sessions WHERE expires_at<now();
        DELETE FROM public.breakglass_tokens WHERE expires_at<now()-interval '1 day';
    $$;
    """,
    # 3: constrain data supplied by the runtime role, including compromised writers.
    """
    ALTER TABLE audit_log ADD CONSTRAINT audit_payload_bounds CHECK (
        octet_length(actor) <= 1024 AND octet_length(action) <= 128 AND
        octet_length(target) <= 1024 AND octet_length(user_agent) <= 1200 AND
        octet_length(details::text) <= 16384 AND
        prev_hash ~ '^[0-9a-f]{64}$' AND hash ~ '^[0-9a-f]{64}$');
    ALTER TABLE sessions ADD CONSTRAINT session_token_bounds CHECK (
        octet_length(id_hash)=32 AND length(csrf_token)=43 AND
        expires_at > created_at AND expires_at <= created_at + interval '24 hours 1 minute');
    ALTER TABLE breakglass_tokens ADD CONSTRAINT breakglass_token_bounds CHECK (
        octet_length(token_hash)=32 AND expires_at > created_at AND
        expires_at <= created_at + interval '11 minutes');
    ALTER TABLE users ADD CONSTRAINT nonempty_user_email CHECK (length(email) > 0);
    """,
    # 4: security events, kept separately from the immutable administrative audit.
    """
    CREATE TABLE security_events (
        id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
        source_id text NOT NULL CHECK (source_id ~ '^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$'),
        facility smallint CHECK (facility BETWEEN 0 AND 23),
        severity smallint CHECK (severity BETWEEN 0 AND 7),
        message text NOT NULL CHECK (octet_length(message) BETWEEN 1 AND 8192),
        rule_id text CHECK (rule_id IN ('auth_failure','firewall_deny','malware_indicator'))
    );
    CREATE INDEX security_events_received_idx ON security_events(received_at DESC,id DESC);
    CREATE INDEX security_events_source_idx ON security_events(source_id,received_at DESC,id DESC);
    CREATE INDEX security_events_alert_idx ON security_events(received_at DESC,id DESC) WHERE rule_id IS NOT NULL;
    CREATE FUNCTION prune_security_events() RETURNS void LANGUAGE sql SECURITY DEFINER
    SET search_path=pg_catalog,public AS $$
        DELETE FROM public.security_events WHERE id IN (
            SELECT id FROM public.security_events WHERE received_at < now()-interval '24 hours'
            ORDER BY received_at,id LIMIT 10000
        );
    $$;
    """,
    # 5 (Phase 0.1 hardening): privileged changes are only possible through
    # functions that authenticate a live super-admin session token, and the
    # database refuses to COMMIT any role/active/user/break-glass change that has
    # no matching audit record written in the same transaction. A stolen web-app
    # DB password alone can no longer escalate privileges silently.
    """
    ALTER TABLE audit_log ADD COLUMN txid xid8 NOT NULL DEFAULT pg_current_xact_id();
    CREATE INDEX audit_txid_idx ON audit_log(txid);

    CREATE FUNCTION admin_actor(p_token text, p_idle_minutes integer) RETURNS public.users
    LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    DECLARE a public.users;
    BEGIN
        IF p_token IS NULL OR length(p_token) NOT BETWEEN 20 AND 100
           OR p_idle_minutes IS NULL OR p_idle_minutes NOT BETWEEN 1 AND 60 THEN
            RAISE EXCEPTION 'not authorized' USING ERRCODE = '42501';
        END IF;
        PERFORM pg_advisory_xact_lock(7313);
        SELECT u.* INTO a FROM public.sessions s JOIN public.users u ON u.id = s.user_id
         WHERE s.id_hash = sha256(convert_to(p_token, 'UTF8'))
           AND s.expires_at > clock_timestamp()
           AND s.last_seen_at > clock_timestamp() - p_idle_minutes * interval '1 minute'
           AND u.active AND u.role = 'super_admin'
         FOR UPDATE OF s;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'not authorized' USING ERRCODE = '42501';
        END IF;
        RETURN a;
    END $$;

    CREATE FUNCTION admin_create_user(p_token text, p_idle_minutes integer, p_email text,
                                      p_oid uuid, p_role text) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    DECLARE a public.users; new_id integer;
    BEGIN
        a := public.admin_actor(p_token, p_idle_minutes);
        INSERT INTO public.users (email, entra_oid, role) VALUES (p_email, p_oid, p_role)
        RETURNING id INTO new_id;
        RETURN new_id;
    END $$;

    CREATE FUNCTION admin_set_role(p_token text, p_idle_minutes integer, p_target integer,
                                   p_role text) RETURNS TABLE(email text, old_role text)
    LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    DECLARE a public.users; t public.users;
    BEGIN
        a := public.admin_actor(p_token, p_idle_minutes);
        IF p_target = a.id THEN
            RAISE EXCEPTION 'You cannot change your own role' USING ERRCODE = 'P0001';
        END IF;
        SELECT * INTO t FROM public.users u WHERE u.id = p_target FOR UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION 'no such user' USING ERRCODE = 'P0002'; END IF;
        UPDATE public.users u SET role = p_role WHERE u.id = p_target;
        email := t.email; old_role := t.role;
        RETURN NEXT;
    END $$;

    CREATE FUNCTION admin_set_active(p_token text, p_idle_minutes integer, p_target integer,
                                     p_active boolean) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    DECLARE a public.users; t public.users;
    BEGIN
        a := public.admin_actor(p_token, p_idle_minutes);
        IF p_target = a.id THEN
            RAISE EXCEPTION 'You cannot deactivate yourself' USING ERRCODE = 'P0001';
        END IF;
        SELECT * INTO t FROM public.users u WHERE u.id = p_target FOR UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION 'no such user' USING ERRCODE = 'P0002'; END IF;
        UPDATE public.users u SET active = p_active WHERE u.id = p_target;
        IF NOT EXISTS (SELECT 1 FROM public.users u WHERE u.role = 'super_admin' AND u.active) THEN
            RAISE EXCEPTION 'At least one super admin must stay active' USING ERRCODE = 'P0001';
        END IF;
        RETURN t.email;
    END $$;

    -- First sign-in only: works while the users table is empty.
    CREATE FUNCTION bootstrap_first_admin(p_oid uuid, p_email text) RETURNS SETOF public.users
    LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    DECLARE u public.users;
    BEGIN
        PERFORM pg_advisory_xact_lock(7313);
        IF EXISTS (SELECT 1 FROM public.users) THEN RETURN; END IF;
        INSERT INTO public.users (email, entra_oid, role)
        VALUES (p_email, p_oid, 'super_admin') RETURNING * INTO u;
        RETURN NEXT u;
    END $$;

    CREATE FUNCTION require_audit_record() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    DECLARE want text[]; who text; by_actor boolean := false;
    BEGIN
        IF TG_TABLE_NAME = 'users' THEN
            who := NEW.email;
            IF TG_OP = 'INSERT' THEN want := ARRAY['user.created'];
            ELSIF OLD.role IS DISTINCT FROM NEW.role THEN want := ARRAY['user.role_changed'];
            ELSIF OLD.active IS DISTINCT FROM NEW.active THEN want := ARRAY['user.activated','user.deactivated'];
            ELSE RETURN NULL;
            END IF;
        ELSE
            SELECT u.email INTO who FROM public.users u WHERE u.id = NEW.user_id;
            IF TG_OP = 'INSERT' THEN want := ARRAY['auth.breakglass.token_created'];
            ELSIF OLD.used_at IS NULL AND NEW.used_at IS NOT NULL THEN
                want := ARRAY['auth.breakglass.login']; by_actor := true;
            ELSE RETURN NULL;
            END IF;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM public.audit_log l WHERE l.txid = pg_current_xact_id()
                       AND l.action = ANY(want)
                       AND (CASE WHEN by_actor THEN l.actor ELSE l.target END) = who) THEN
            RAISE EXCEPTION 'privileged change on % requires an audit record in the same transaction',
                TG_TABLE_NAME USING ERRCODE = 'SIA01';
        END IF;
        RETURN NULL;
    END $$;
    CREATE CONSTRAINT TRIGGER users_require_audit AFTER INSERT OR UPDATE OF role, active ON users
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_audit_record();
    CREATE CONSTRAINT TRIGGER breakglass_require_audit AFTER INSERT OR UPDATE OF used_at ON breakglass_tokens
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_audit_record();

    -- Worker-reported integrity status, so tampering is visible in the UI and not
    -- only as a missing external heartbeat.
    CREATE TABLE audit_verification (
        id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        checked_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
        ok            boolean NOT NULL,
        full_scan     boolean NOT NULL,
        checkpoint_id bigint NOT NULL CHECK (checkpoint_id >= 0),
        detail        text NOT NULL CHECK (detail ~ '^[A-Za-z0-9_ .:()-]{0,160}$')
    );
    CREATE INDEX audit_verification_time_idx ON audit_verification(checked_at DESC);

    CREATE OR REPLACE FUNCTION cleanup_expired() RETURNS void LANGUAGE sql SECURITY DEFINER
    SET search_path=pg_catalog,public AS $$
        DELETE FROM public.sessions WHERE expires_at<now();
        DELETE FROM public.breakglass_tokens WHERE expires_at<now()-interval '1 day';
        DELETE FROM public.audit_verification WHERE checked_at<now()-interval '30 days';
    $$;
    """,
    # 6 (Phase 1): customers (MSP clients), staff assignments and a customer scope
    # that is derived only from a live SSO session token, never from request input.
    # Row-level security on the two tables makes the web role see exactly the
    # customers its current session is scoped to; writes go only through the
    # session-authenticated SECURITY DEFINER functions, and a deferred trigger
    # refuses to COMMIT any customer or assignment change without an audit record.
    #
    # RLS design: policies are FORCEd, so the table owner is subject to them too.
    # The owner (which owns every SECURITY DEFINER function, including the scope
    # function the policies call) gets its own permissive "definer" policy, and the
    # scope policies apply only TO the web role. The scope function therefore reads
    # these tables under the definer policy alone and never re-enters the scope
    # policy (no recursion). The web role's name is supplied by the migration
    # runner (siem.migrate_app_role) and kept current by grant_roles().
    """
    CREATE TABLE customers (
        id         integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        slug       text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,31}$'),
        name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 100 AND name !~ '[[:cntrl:]]'),
        active     boolean NOT NULL DEFAULT true,
        created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE staff_customers (
        user_id     integer NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        customer_id integer NOT NULL REFERENCES customers(id),
        PRIMARY KEY (user_id, customer_id)
    );
    CREATE INDEX staff_customers_customer_idx ON staff_customers(customer_id);

    -- Customer ids the given session may see. Read-only: it does not refresh
    -- last_seen_at, and it never raises for an unknown or malformed token.
    -- Break-glass sessions get no customer scope at all.
    CREATE FUNCTION session_customer_ids(p_token text, p_idle integer) RETURNS integer[]
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    DECLARE uid integer; urole text;
    BEGIN
        IF p_token IS NULL OR length(p_token) NOT BETWEEN 20 AND 100
           OR p_idle IS NULL OR p_idle NOT BETWEEN 1 AND 60 THEN
            RETURN '{}';
        END IF;
        SELECT u.id, u.role INTO uid, urole
          FROM public.sessions s JOIN public.users u ON u.id = s.user_id
         WHERE s.id_hash = sha256(convert_to(p_token, 'UTF8'))
           AND s.via = 'sso'
           AND s.expires_at > clock_timestamp()
           AND s.last_seen_at > clock_timestamp() - p_idle * interval '1 minute'
           AND u.active;
        IF NOT FOUND THEN
            RETURN '{}';
        END IF;
        IF urole = 'super_admin' THEN
            RETURN coalesce((SELECT array_agg(c.id ORDER BY c.id) FROM public.customers c
                             WHERE c.active), '{}');
        END IF;
        RETURN coalesce((SELECT array_agg(c.id ORDER BY c.id)
                           FROM public.staff_customers sc
                           JOIN public.customers c ON c.id = sc.customer_id
                          WHERE sc.user_id = uid AND c.active), '{}');
    END $$;

    ALTER TABLE customers ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
    ALTER TABLE staff_customers ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
    CREATE POLICY customers_definer ON customers FOR ALL TO CURRENT_USER
        USING (true) WITH CHECK (true);
    CREATE POLICY staff_customers_definer ON staff_customers FOR ALL TO CURRENT_USER
        USING (true) WITH CHECK (true);
    DO $mig$
    DECLARE app text := current_setting('siem.migrate_app_role', true);
    BEGIN
        IF app IS NULL OR app = '' OR app = current_user THEN
            RAISE EXCEPTION 'migration 6 needs the web role name in siem.migrate_app_role';
        END IF;
        EXECUTE format($p$CREATE POLICY customers_scope ON public.customers FOR SELECT TO %I
            USING (id = ANY ((SELECT public.session_customer_ids(current_setting('siem.session', true), 60))::integer[])) $p$, app);
        EXECUTE format($p$CREATE POLICY staff_customers_scope ON public.staff_customers FOR SELECT TO %I
            USING (customer_id = ANY ((SELECT public.session_customer_ids(current_setting('siem.session', true), 60))::integer[])) $p$, app);
    END $mig$;

    CREATE FUNCTION admin_create_customer(p_token text, p_idle integer, p_slug text,
                                          p_name text) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    DECLARE a public.users; new_id integer;
    BEGIN
        a := public.admin_actor(p_token, p_idle);
        INSERT INTO public.customers (slug, name) VALUES (p_slug, p_name) RETURNING id INTO new_id;
        RETURN new_id;
    END $$;

    CREATE FUNCTION admin_set_customer_active(p_token text, p_idle integer, p_customer integer,
                                              p_active boolean) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    DECLARE a public.users; c public.customers;
    BEGIN
        a := public.admin_actor(p_token, p_idle);
        IF p_active IS NULL THEN RAISE EXCEPTION 'active flag required' USING ERRCODE = '22004'; END IF;
        SELECT * INTO c FROM public.customers x WHERE x.id = p_customer FOR UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION 'no such customer' USING ERRCODE = 'P0002'; END IF;
        UPDATE public.customers x SET active = p_active WHERE x.id = p_customer;
        RETURN c.slug;
    END $$;

    CREATE FUNCTION admin_assign_staff(p_token text, p_idle integer, p_user integer,
                                       p_customer integer, p_assigned boolean) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    DECLARE a public.users; c public.customers;
    BEGIN
        a := public.admin_actor(p_token, p_idle);
        IF p_assigned IS NULL THEN RAISE EXCEPTION 'assigned flag required' USING ERRCODE = '22004'; END IF;
        PERFORM 1 FROM public.users u WHERE u.id = p_user FOR SHARE;
        IF NOT FOUND THEN RAISE EXCEPTION 'no such user' USING ERRCODE = 'P0002'; END IF;
        SELECT * INTO c FROM public.customers x WHERE x.id = p_customer FOR SHARE;
        IF NOT FOUND THEN RAISE EXCEPTION 'no such customer' USING ERRCODE = 'P0002'; END IF;
        IF p_assigned THEN
            INSERT INTO public.staff_customers (user_id, customer_id) VALUES (p_user, p_customer)
            ON CONFLICT DO NOTHING;
        ELSE
            DELETE FROM public.staff_customers sc WHERE sc.user_id = p_user AND sc.customer_id = p_customer;
        END IF;
        RETURN c.slug;
    END $$;

    CREATE FUNCTION require_tenant_audit() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    DECLARE want text; who text;
    BEGIN
        IF TG_TABLE_NAME = 'customers' THEN
            who := NEW.slug;
            IF TG_OP = 'INSERT' THEN want := 'customer.created';
            ELSIF OLD.active IS DISTINCT FROM NEW.active THEN
                want := CASE WHEN NEW.active THEN 'customer.activated' ELSE 'customer.deactivated' END;
            ELSE RETURN NULL;
            END IF;
        ELSIF TG_OP = 'INSERT' THEN
            want := 'customer.staff_assigned';
            SELECT c.slug INTO who FROM public.customers c WHERE c.id = NEW.customer_id;
        ELSE
            want := 'customer.staff_removed';
            SELECT c.slug INTO who FROM public.customers c WHERE c.id = OLD.customer_id;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM public.audit_log l WHERE l.txid = pg_current_xact_id()
                       AND l.action = want AND l.target = who) THEN
            RAISE EXCEPTION 'customer change on % requires an audit record in the same transaction',
                TG_TABLE_NAME USING ERRCODE = 'SIA01';
        END IF;
        RETURN NULL;
    END $$;
    CREATE CONSTRAINT TRIGGER customers_require_audit AFTER INSERT OR UPDATE OF active ON customers
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_tenant_audit();
    CREATE CONSTRAINT TRIGGER staff_customers_require_audit AFTER INSERT OR DELETE ON staff_customers
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_tenant_audit();
    """,
]

AUDIT_INSERT_COLUMNS = ("id, ts, actor, action, target, severity, ip, user_agent, details, "
                        "prev_hash, hash")


ADMIN_FUNCTIONS = (
    "admin_create_user(text, integer, text, uuid, text)",
    "admin_set_role(text, integer, integer, text)",
    "admin_set_active(text, integer, integer, boolean)",
    "admin_create_customer(text, integer, text, text)",
    "admin_set_customer_active(text, integer, integer, boolean)",
    "admin_assign_staff(text, integer, integer, integer, boolean)",
    "session_customer_ids(text, integer)",
)

# Session-creating functions: only the login service's role may call them (N12).
SIGN_IN_FUNCTIONS = (
    "bootstrap_first_admin(uuid, text)",
    "consume_breakglass(bytea)",
)

# Row-level security policies that apply only to the web role (see migration 6).
APP_SCOPED_POLICIES = (
    ("customers_scope", "customers"),
    ("staff_customers_scope", "staff_customers"),
)


def role_grants(app_role, worker_role, emergency_role, ingest_role, auth_role) -> dict[str, list[str]]:
    """The complete, deny-by-default privilege set for every runtime role."""
    return {
        app_role: [
            # No INSERT and no UPDATE(role, active) on users: privileged changes
            # go through the session-authenticated SECURITY DEFINER functions.
            # No INSERT on sessions and no sign-in functions (N12): the web role
            # only authenticates, refreshes and expires sessions the login service made.
            "GRANT SELECT ON users TO {r}",
            "GRANT UPDATE (last_login_at) ON users TO {r}",
            "GRANT SELECT, DELETE ON sessions TO {r}",
            "GRANT UPDATE (last_seen_at) ON sessions TO {r}",
            f"GRANT SELECT, INSERT ({AUDIT_INSERT_COLUMNS}) ON audit_log TO {{r}}",
            "GRANT SELECT ON audit_head, audit_verification TO {r}",
            *[f"GRANT EXECUTE ON FUNCTION {fn} TO {{r}}" for fn in ADMIN_FUNCTIONS],
            "GRANT SELECT ON security_events TO {r}",
            # Customer data is read-only for the web role and filtered by RLS to
            # the customers the current session is scoped to.
            "GRANT SELECT ON customers, staff_customers TO {r}",
        ],
        worker_role: [
            "GRANT SELECT ON audit_log, audit_head TO {r}",
            "GRANT INSERT (ok, full_scan, checkpoint_id, detail) ON audit_verification TO {r}",
            "GRANT EXECUTE ON FUNCTION cleanup_expired() TO {r}",
            "GRANT EXECUTE ON FUNCTION prune_security_events() TO {r}",
        ],
        emergency_role: [
            "GRANT SELECT (id, email, role, active) ON users TO {r}",
            "GRANT INSERT (token_hash, user_id, expires_at) ON breakglass_tokens TO {r}",
            f"GRANT SELECT, INSERT ({AUDIT_INSERT_COLUMNS}) ON audit_log TO {{r}}",
            "GRANT SELECT ON audit_head TO {r}",
        ],
        ingest_role: [
            "GRANT INSERT (source_id, facility, severity, message, rule_id) ON security_events TO {r}",
        ],
        # Login service (siem.auth_main): the ONLY role that can create a session.
        # Nothing on customers/staff_customers, events, break-glass tokens or the
        # admin functions; no UPDATE on sessions (logout deletes, never refreshes).
        auth_role: [
            "GRANT SELECT ON users TO {r}",
            "GRANT UPDATE (last_login_at) ON users TO {r}",
            "GRANT SELECT, INSERT, DELETE ON sessions TO {r}",
            f"GRANT SELECT, INSERT ({AUDIT_INSERT_COLUMNS}) ON audit_log TO {{r}}",
            "GRANT SELECT ON audit_head TO {r}",
            *[f"GRANT EXECUTE ON FUNCTION {fn} TO {{r}}" for fn in SIGN_IN_FUNCTIONS],
        ],
    }


def grant_roles(cur, app_role, worker_role, emergency_role, ingest_role, auth_role):
    grants = role_grants(app_role, worker_role, emergency_role, ingest_role, auth_role)
    if len(grants) != 5 or env("SIEM_DB_OWNER_USER", required=True) in grants:
        raise ValueError("Database service roles must be distinct")
    cur.execute("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC")
    for role, statements in grants.items():
        ident = pgsql.Identifier(role)
        # Reset first, so privileges removed in a newer release are really gone
        # after an upgrade (GRANT alone never takes anything away).
        for reset in ["REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {r}",
                      "REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {r}",
                      "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM {r}",
                      "REVOKE ALL ON SCHEMA public FROM {r}"]:
            cur.execute(pgsql.SQL(reset).format(r=ident))
        for statement in ["GRANT USAGE ON SCHEMA public TO {r}", *statements]:
            cur.execute(pgsql.SQL(statement).format(r=ident))
    # Keep the customer-scope policies attached to the current web role, so a
    # renamed role never inherits a stale policy target.
    for policy, table in APP_SCOPED_POLICIES:
        cur.execute(pgsql.SQL("ALTER POLICY {p} ON {t} TO {r}").format(
            p=pgsql.Identifier(policy), t=pgsql.Identifier(table), r=pgsql.Identifier(app_role)))


def main() -> int:
    dsn = db_dsn("SIEM_DB_OWNER_USER", "db_owner_password")
    app_role = env("SIEM_DB_APP_USER", required=True)
    with psycopg.connect(dsn, autocommit=False) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls FROM pg_roles WHERE rolname=current_user")
            if any(cur.fetchone()):
                raise RuntimeError("Migration account is overprivileged. Fresh Phase 0.2 database required; preserve old evidence.")
            cur.execute("SELECT pg_advisory_xact_lock(7311)")
            cur.execute(
                "CREATE TABLE IF NOT EXISTS schema_version (version integer NOT NULL)"
            )
            cur.execute("SELECT set_config('siem.migrate_app_role', %s, true)", (app_role,))
            cur.execute("SELECT coalesce(max(version), 0) FROM schema_version")
            current = cur.fetchone()[0]
            if current not in (0, 2, 3, 4, 5, 6):
                raise RuntimeError("Unknown schema version; Phase 0 (v1) databases require a fresh install. Preserve old audit evidence offline.")
            for i, sql in enumerate(MIGRATIONS, start=2):
                if i <= current:
                    continue
                print(f"Applying migration {i}")
                cur.execute(sql)
                cur.execute("INSERT INTO schema_version (version) VALUES (%s)", (i,))
            cur.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
            grant_roles(cur, app_role, env("SIEM_DB_WORKER_USER", required=True),
                        env("SIEM_DB_EMERGENCY_USER", required=True),
                        env("SIEM_DB_INGEST_USER", required=True),
                        env("SIEM_DB_AUTH_USER", required=True))
        conn.commit()
    print("Database schema is up to date.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
