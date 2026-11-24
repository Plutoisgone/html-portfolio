"""Fixed, parameterized queries for the single-tenant event console."""
from .events import RULES, SOURCE_RE


def search_query(source='', term='', rule=''):
    if source and not SOURCE_RE.fullmatch(source):
        raise ValueError('Invalid source filter')
    if rule not in ('', 'any', *RULES):
        raise ValueError('Invalid rule filter')
    if len(term.encode('utf-8')) > 128 or any(ord(c) < 32 or ord(c)==127 for c in term):
        raise ValueError('Invalid search term')
    where = ["received_at >= now() - interval '24 hours'"]
    params = []
    if source:
        where.append('source_id = %s')
        params.append(source)
    if term:
        where.append('strpos(message, %s) > 0')
        params.append(term)
    if rule == 'any':
        where.append('rule_id IS NOT NULL')
    elif rule:
        where.append('rule_id = %s')
        params.append(rule)
    return ('SELECT id, received_at, source_id, facility, severity, message, rule_id '
            'FROM public.security_events WHERE ' + ' AND '.join(where) +
            ' ORDER BY received_at DESC,id DESC LIMIT 100', tuple(params))
