# -*- coding: utf-8 -*-

# main entry point for ViaUATEndpoint

from ast import Delete
import ipaddress
import json
import os
import re
import time
import yaml

from typing import Optional, List
from enum import Enum

from fastapi import FastAPI, Request, Response, Path, Depends
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

DEFAULT_CONFIGS = [
    {
        'src_cidr': 'ALL',
        'path_re_match': 'ALL',
        'method': 'ALL',
        'header': None,
        'delay_ms': 0,
        'status_code': 200,
        'body': '{}',
        'mime_type': 'application/json',
        'ip_version': 4
    }
]

DEBUG = False

class Config(BaseModel):
    src_cidr: Optional[str] = 'ALL'
    path_re_match: Optional[str] = 'ALL'
    header: Optional[str] = None
    delay_ms: Optional[int] = 0
    status_code: Optional[int] = 200
    body: Optional[str] = '{}'
    mime_type: Optional[str] = 'application/json'
    ip_version: Optional[int] = 4


def load_config():
    global DEFAULT_CONFIGS, DEBUG
    cf_path = os.getenv(
        'CONFIG_FILE',
        "%s/config.yaml" % os.path.dirname(os.path.realpath(__file__))
    )
    if os.path.exists(cf_path):
        with open(cf_path) as cf:
            try:
                cf_obj = yaml.safe_load(cf)
                DEFAULT_CONFIGS = cf_obj['configs']
                DEBUG = cf_obj['debug']
            except Exception as error:
                print("Can not load config.yaml file")


app = FastAPI(
    title = 'ViaUATEndpoint Application',
    description= '''
    Application which allows you configure the response status code,
    add response latency, and return body based on matching headers,
    HTTP method, and a path regular expression match.
    ''',
    version='1.0.0',
    contact={
        "name": "John Gruber",
        "email": "j.gruber@f5.com"
    },
    license_info={
        "name": "Apache 2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0.html"
    }
)
app.mount('/static', StaticFiles(directory='static', html=True), name='static')
existing_configs = DEFAULT_CONFIGS


@app.on_event('startup')
async def startup_event():
    global existing_configs
    load_config()
    existing_configs = DEFAULT_CONFIGS


def match_config(client_ips):
    for client in client_ips:
        if client:
            for existing_config in existing_configs:
                if existing_config['ip_version'] == 4 and not existing_config['src_cidr'] == 'ALL':
                    try:
                        if ipaddress.IPv4Address(client) in ipaddress.IPv4Network(existing_config['src_cidr']):
                            return existing_config
                    except:
                        pass
                if existing_config['ip_version'] == 6 and not existing_config['src_cidr'] == 'ALL':
                    try:
                        if ipaddress.IPv6Address(client) in ipaddress.IPv6Network(existing_config['src_cidr']):
                            return existing_config
                    except:
                        pass
            for existing_config in existing_configs:
                if existing_config['src_cidr'] == 'ALL':
                    return existing_config
            return DEFAULT_CONFIGS[0]
    return DEFAULT_CONFIGS[0]


def execute_policy(policy, request):
    matched = False
    initial_timestamp = time.time()
    debug_body = {
        'initial_timestamp': initial_timestamp,
        'delayed_timestamp': initial_timestamp,
        'status_code': DEFAULT_CONFIGS[0]['status_code'],
        'mime_type': DEFAULT_CONFIGS[0]['mime_type']
    }
    # Affirm header
    header_match = False
    if policy['header']:
        for header in request.headers.raw:
            if header[0].lower() == policy['header']:
                header_match = True
    else:
        header_match = True
    # Affirm method
    method_match = False
    if policy['method'] == 'ALL' or policy['method'] == request.method:
        method_match = True
    else:
        method_match = False
    # Affirm path regex
    path_regex_match = False
    if policy['path_re_match'] == 'ALL':
        path_regex_match = True
    else:
        if policy['path_re_match']:
            try:
                p = re.compile(policy['path_re_match'])
                if p.match(request.url.path):
                    path_regex_match = True
            except:
                pass
    # policy
    if header_match and method_match and path_regex_match:
        matched = True
    # execute matched policy
    if matched:
        if policy['delay_ms'] > 0:
            time.sleep((policy['delay_ms']/1000))
        debug_body['delayed_timestamp'] = time.time()
        debug_body['status_code'] = policy['status_code']
        debug_body['mime_type'] = policy['mime_type']
        debug_body['client_ip'] = request.client.host
        if DEBUG:
            # return DEBUG response
            return Response(
                content=json.dumps(debug_body, indent=4, sort_keys=False),
                status_code=policy['status_code'],
                media_type=policy['mime_type'],
            )
        else:
            # return policy matched response
            return Response(
                content=policy['body'],
                status_code=policy['status_code'],
                media_type=policy['mime_type']
            )

    if DEBUG:
        # return default DEBUG response
        debug_body['client_ip'] = request.client.host
        return Response(
            content=json.dumps(debug_body, indent=4, sort_keys=False),
            status_code=DEFAULT_CONFIGS[0]['status_code'],
            media_type=DEFAULT_CONFIGS[0]['mime_type']
        )
    else:
        # return default response
        return Response(
            content=DEFAULT_CONFIGS[0]['body'],
            status_code=DEFAULT_CONFIGS[0]['status_code'],
            media_type=DEFAULT_CONFIGS[0]['mime_type']
        )


def delete_matched_config(policy):
    global existing_configs
    new_configs = []
    for config in existing_configs:
        json_policy = json.dumps(policy)
        json_config = json.dumps(config)
        if not json_policy == json_config:
            new_configs.append(config)
    existing_configs = new_configs


@app.get('/configs/', response_model=List[Config])
async def config():
    return existing_configs


@app.post('/configs/', response_model=List[Config])
async def create_config(config: Config):
    new_configs = []
    for existing_config in existing_configs:
        if existing_config['src_cidr'] == config['src_cidr']:
            # update existing ALL config
            if config['src_cidr'] == 'ALL':
                new_configs.append(config)
            else:
                # validate the src_cidr is a proper CIDR (v4 or v6)
                try:
                    ipaddress.IPv4Network(config['src_cidr'])
                    config['ip_version'] = 4
                    new_configs.append(config)
                except:
                    try:
                        ipaddress.IPv6Address(config['src_cidr'])
                        config['ip_version'] = 6
                        new_configs.append(config)
                    except:
                        pass
        else:
            # persist existing
            new_configs.append(existing_config)
    existing_config = new_configs
    return existing_configs


class DeleteParams:
    def __init__(
        self,
        src_ip: str = Path(
            description='''Client source IP to match a policy to delete.
            The first policy to match is deleted.''')
    ):
        self.src_ip = src_ip


@app.delete('/configs/{src_ip}', response_model=List[Config])
async def delete_config(src_ip: DeleteParams = Depends()):
    global existing_configs
    if src_ip == 'ALL':
        existing_configs = DEFAULT_CONFIGS
        return existing_configs
    existing_configs = delete_matched_config(match_config(src_ip))
    return existing_configs


@app.get('/{path_name:path}')
async def get_response(path_name: str, request: Request, response: Response):
    client_host = request.client.host
    origin_ip = None
    forward_ip = None
    x = 'x-forwarded-for'.encode('utf-8')
    for header in request.headers.raw:
        if header[0].lower() == x:
            origin_ip, forward_ip = re.split(', ', header[1].decode('utf-8'))
    return execute_policy(match_config([origin_ip, forward_ip, client_host]), request)


@app.post('/{path_name:path}')
async def post_response(path_value: str, request: Request, response: Response):
    client_host = request.client.host
    origin_ip = None
    forward_ip = None
    x = 'x-forwarded-for'.encode('utf-8')
    for header in request.headers.raw:
        if header[0].lower() == x:
            origin_ip, forward_ip = re.split(', ', header[1].decode('utf-8'))
    return execute_policy(match_config([origin_ip, forward_ip, client_host]), request)


@app.put('/{path_value:path}')
async def put_response(path_value: str, request: Request, response: Response):
    client_host = request.client.host
    origin_ip = None
    forward_ip = None
    x = 'x-forwarded-for'.encode('utf-8')
    for header in request.headers.raw:
        if header[0].lower() == x:
            origin_ip, forward_ip = re.split(', ', header[1].decode('utf-8'))
    return execute_policy(match_config([origin_ip, forward_ip, client_host]), request)


@app.patch('/{path_value:path}')
async def patch_response(path_value: str, request: Request, response: Response):
    client_host = request.client.host
    origin_ip = None
    forward_ip = None
    x = 'x-forwarded-for'.encode('utf-8')
    for header in request.headers.raw:
        if header[0].lower() == x:
            origin_ip, forward_ip = re.split(', ', header[1].decode('utf-8'))
    return execute_policy(match_config([origin_ip, forward_ip, client_host]), request)


@app.head('/{path_value:path}')
async def head_response(path_value: str, request: Request, response: Response):
    client_host = request.client.host
    origin_ip = None
    forward_ip = None
    x = 'x-forwarded-for'.encode('utf-8')
    for header in request.headers.raw:
        if header[0].lower() == x:
            origin_ip, forward_ip = re.split(', ', header[1].decode('utf-8'))
    return execute_policy(match_config([origin_ip, forward_ip, client_host]), request)


@app.delete('/{path_value:path}')
async def delete_response(path_value: str, request: Request, response: Response):
    client_host = request.client.host
    origin_ip = None
    forward_ip = None
    x = 'x-forwarded-for'.encode('utf-8')
    for header in request.headers.raw:
        if header[0].lower() == x:
            origin_ip, forward_ip = re.split(', ', header[1].decode('utf-8'))
    return execute_policy(match_config([origin_ip, forward_ip, client_host]), request)
