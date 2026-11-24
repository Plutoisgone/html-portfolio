"""Bounded syslog normalization and illustrative per-event detection rules.

All message fields are untrusted. The authenticated source ID is assigned by
collector configuration, never extracted from the message.
"""
from dataclasses import dataclass
import re
import shlex

MAX_FRAME = 8192
SOURCE_RE = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}\Z')
PRI_RE = re.compile(r'^<([0-9]{1,3})>')
RULES = ('auth_failure', 'firewall_deny', 'malware_indicator')


@dataclass(frozen=True)
class Event:
    source: str
    facility: int | None
    severity: int | None
    message: str
    rule: str | None


def normalize(source: str, frame: bytes) -> Event:
    if not SOURCE_RE.fullmatch(source) or not 1 <= len(frame) <= MAX_FRAME:
        raise ValueError('Invalid source or frame length')
    raw = frame.decode('utf-8', errors='strict')
    # Reject controls, including terminal escapes and embedded record separators.
    if any(ord(c) < 32 and c != '\t' or 127 <= ord(c) <= 159 for c in raw):
        raise ValueError('Invalid control character')
    match = PRI_RE.match(raw)
    pri = int(match.group(1)) if match else None
    if pri is not None and pri > 191:
        raise ValueError('Invalid syslog priority')
    # Conservative token-based matching; not a complete vendor parser.
    fields = {}
    try:
        for token in shlex.split(raw[match.end():] if match else raw):
            key, sep, value = token.partition('=')
            key = key.lower()
            if sep and key in {'action','status','event','category','log_subtype','log_type'}:
                if key in fields:  # ambiguous duplicate fields: no rule match
                    fields = {}
                    break
                fields[key] = value.lower()
    except ValueError:
        fields = {}
    rule = None
    if fields.get('event') in {'login_failed','authentication_failed'} or (
        fields.get('category') in {'authentication','auth'} and fields.get('status') in {'failed','failure'}
    ):
        rule = 'auth_failure'
    elif fields.get('action') in {'deny','drop','blocked','reject'} or fields.get('status') == 'deny':
        rule = 'firewall_deny'
    elif fields.get('event') == 'malware_detected':
        rule = 'malware_indicator'
    return Event(source, pri // 8 if pri is not None else None,
                 pri % 8 if pri is not None else None, raw, rule)


INSERT_EVENT = ('INSERT INTO public.security_events (source_id, facility, severity, message, rule_id) '
                'VALUES (%s,%s,%s,%s,%s)')


def persist(conn, event: Event):
    conn.execute(INSERT_EVENT, (event.source, event.facility, event.severity, event.message, event.rule))
