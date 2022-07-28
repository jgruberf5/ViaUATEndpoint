import os

from typing import List, Any


DEFAULT_CONFIG_FILE: str = "%s/config.yaml" % os.path.dirname(
    os.path.realpath(__file__))
DEFAULT_POLICIES: List[Any] = [{
    'src_cidr':
    'ALL',
    'path_re_match':
    'ALL',
    'method':
    'ALL',
    'header':
    'NONE',
    'ip_version':
    4,
    'reply_scripts': [{
        'delay_ms': 0,
        'repeat': 0,
        'direct_response_status_code': 200,
        'direct_response_mime_type': 'application/json',
        'direct_response_body': '{}',
        'direct_response_body_encoding': 'NONE'
    }]
}]
DEFAULT_LOG_LEVEL:str = 'INFO'
VALID_HTTP_METHODS: List[str] = [
    'GET', 'POST', 'PUT', 'PATCH', 'HEAD', 'DELETE', 'OPTIONS'
]
VALID_HTTP_STATUS_CODES: List[int] = [
    100, 101, 102, 103, 200, 201, 202, 203, 204, 205, 206, 300, 301, 302, 303,
    304, 307, 308, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411,
    412, 413, 414, 415, 416, 417, 418, 422, 425, 426, 428, 429, 431, 451, 500,
    501, 502, 503, 504, 506, 508, 510, 511
]
ACTIONS: List[str] = ['direct_response', 'redirect', 'serve_local']
VALID_DAYS_OF_WEEK = ['SU', 'M', 'T', 'W', 'R', 'F', 'SA']
