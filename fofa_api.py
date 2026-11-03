"""FOFA request/response contract; retry, checkpoint and run policy live outside this module."""

import base64
import json

FOFA_FIELDS = 'host,ip,port,protocol,title,country,region,city,domain,link'
DEFAULT_URL = 'https://fofa.info/api/v1/search/all'


def parse_row(row):
    values = (list(row) + [None] * 10)[:10]
    host, ip, port, protocol, title, country, region, city, domain, link = values
    return {'host': host or '', 'ip': str(ip or ''), 'port': port,
            'protocol': (protocol or '').lower(), 'title': title or '',
            'country': country or '', 'region': region or '', 'city': city or '',
            'domain': domain or '', 'link': link or ''}


def fetch(cfg, query, *, request_get, size=10000, full=False, page=1):
    params = {'qbase64': base64.b64encode(query.encode('utf-8')).decode('ascii'),
              'email': cfg['email'], 'key': cfg['token'], 'page': page,
              'size': min(int(size), 10000), 'full': 'true' if full else 'false',
              'fields': FOFA_FIELDS}
    code, text = request_get(cfg.get('url') or DEFAULT_URL, params=params,
                            timeout=cfg.get('timeout', 30))
    if code != 200:
        # Never echo a provider body or exception containing an API key.
        return [], 0, f'HTTP {code}'
    try:
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError('JSON 不是对象')
    except (ValueError, TypeError):
        return [], 0, 'JSON 解析失败'
    if data.get('error'):
        message = str(data.get('errmsg') or 'FOFA 返回未知错误')
        for secret in (cfg.get('token'), cfg.get('email')):
            if secret:
                message = message.replace(secret, '[REDACTED]')
        return [], 0, message
    total = data.get('size')
    if isinstance(total, str) and total.strip().isdecimal():
        total = int(total.strip())
    if type(total) is not int or total < 0:
        return [], 0, 'FOFA total 无效, 拒绝标记完成'
    raw = data.get('results') or []
    if not isinstance(raw, list) or any(not isinstance(row, (list, tuple)) for row in raw):
        return [], 0, 'FOFA results 无效, 拒绝标记完成'
    try:
        rows = [parse_row(row) for row in raw]
    except (ValueError, TypeError, AttributeError):
        return [], 0, 'FOFA 行格式异常, 拒绝标记完成'
    return rows, total, None
