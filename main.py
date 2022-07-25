# -*- coding: utf-8 -*-

# main entry point for ViaUATEndpoint

import base64
import ipaddress
import json
import logging
import logging_config
import os
import re
import requests
import time
import urllib.request as urllibrequest
import urllib.parse as urllibparse
import validators
import yaml

from typing import Mapping, Optional, List, Dict, Union, Any
from enum import Enum

from fastapi import FastAPI, Request, Response, Path, Depends, Query, HTTPException
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
from starlette.background import BackgroundTask
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError, validator

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
DEBUG: bool = False
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

logger = logging_config.init_logging()

last_id: int = 0
policies: dict = {}


class RunScript(BaseModel):
    delay_ms: Union[int, None] = Field(
        default=-1,
        title='Delay in milliseconds',
        description=
        'Delay the response to this request by this many milliseconds')
    repeat: Union[int, None] = Field(
        default=0,
        title='Repeat script',
        description=
        'How many times to repeat this script step before progressing to the next'
    )
    inject_headers: Union[List[Mapping[str, str]], None] = Field(
        default=[],
        title='Headers to Inject',
        description='Headers to inject in the response')
    action: Union[str, None] = Field(
        default='direct_response',
        title='Script action',
        description=
        'What action to take: direct_response, redirect or serve_local')
    direct_response_status_code: Union[int, None] = Field(
        default=200,
        title='HTTP response status code',
        description='The HTTP status code to return')
    direct_response_mime_type: Union[str, None] = Field(
        default='application/json',
        title='MIME type to return',
        description='MIME type of the return body')
    direct_response_body: Union[str, None] = Field(
        default='{}',
        title='Body content',
        description='Response body content')
    direct_response_body_encoding: Union[str, None] = Field(
        default='NONE',
        title='Body content encoding',
        description=
        'Either do not encode the body content (NONE) or else base64encode it (BASE64)'
    )
    redirect_status_code: Union[str, None] = Field(
        default=307,
        title='Redirect Status Code',
        description='Which redirect status code to use 301,302,307')
    redirect_url: Union[str, None] = Field(
        default='NONE',
        title='Redirect URL',
        description='URL to redirect the request')
    serve_local_file_path: Union[str, None] = Field(
        default='NONE',
        title='Serve Local File',
        description='Local file path for the file to serve for the request')

    @validator('action')
    def action_needs_to_be_in_supported_actions(cls, v):
        if v not in ACTIONS:
            raise HTTPException(status_code=400,
                                detail='body_encoding must be in %s' % ACTIONS)
        return v

    @validator('direct_response_status_code')
    def status_code_must_be_in_list(cls, v):
        if v not in VALID_HTTP_STATUS_CODES:
            raise HTTPException(
                status_code=400,
                detail='status_code must be a valid HTTP status code')
        return v

    @validator('direct_response_mime_type')
    def mime_type_must_include_category_and_type(cls, v):
        if ('/' not in v) or (v.find('/') < 1):
            raise HTTPException(
                status_code=400,
                detail='mime_type must include a category and type')
        return v

    @validator('direct_response_body_encoding')
    def body_encoding_must_be_none_or_base64(cls, v):
        if v not in ['NONE', 'BASE64']:
            raise HTTPException(status_code=400,
                                detail='body_encoding must be NONE or BASE64')
        return v

    @validator('redirect_status_code')
    def redirect_status_code_must_be_in_list(cls, v):
        if v not in [301, 302, 307]:
            raise HTTPException(
                status_code=400,
                detail='redirect_status_code should be 301,302 or 307')
        return v


class Policy(BaseModel):
    id: Union[int, None] = Field(
        default=0,
        title='Policy Id',
        description='Service generated reference to policy')
    src_cidr: Union[str, None] = Field(
        default='ALL',
        title='Client CIDR',
        description='The IPv4 or IPv6 CIDR to match the client request')
    method: Union[str, None] = Field(
        default='ALL',
        title='HTTP Request Method',
        description='The HTTP request method to match the request')
    headers: Union[List[Mapping[str, str]], None] = Field(
        default='NONE',
        title='HTTP headers and values to match',
        description='List of HTTP headers and values to match for the request')
    path_re_match: Union[str, None] = Field(
        default='ALL',
        title='Regular Expression',
        description='HTTP path regular expression match for the request')
    ip_version: Union[int, None] = Field(
        default=4,
        title='IP Version',
        description='The IP version, 4 or 6, to match the request')
    reply_scripts: List[RunScript] = DEFAULT_POLICIES[0]['reply_scripts']


class PolicyCreate(BaseModel):
    src_cidr: Union[str, None] = Field(
        default='ALL',
        title='Client CIDR',
        description='The IPv4 or IPv6 CIDR to match the client request')
    method: Union[str, None] = Field(
        default='ALL',
        title='HTTP Request Method',
        description='The HTTP request method to match the request')
    headers: Union[List[Mapping[str, str]], None] = Field(
        default='NONE',
        title='HTTP headers and values to match',
        description='List of HTTP headers and values to match for the request')
    path_re_match: Union[str, None] = Field(
        default='ALL',
        title='Regular Expression',
        description='HTTP path regular expression match for the request')
    ip_version: Union[int, None] = Field(
        default=4,
        title='IP Version',
        description='The IP version, 4 or 6, to match the request')
    reply_scripts: List[RunScript] = DEFAULT_POLICIES[0]['reply_scripts']

    @validator('src_cidr')
    def src_cidr_must_be_all_or_cidr(cls, v):
        valid_cidr: bool = False
        if v == 'ALL':
            valid_cidr = True
        if not isinstance(validators.ipv4_cidr(v),
                          validators.ValidationFailure):
            valid_cidr = True
        if not isinstance(validators.ipv6_cidr(v),
                          validators.ValidationFailure):
            valid_cidr = True
        if not valid_cidr:
            raise HTTPException(
                status_code=400,
                detail='src_cidr must be ALL or a valid IPv4 or IPv6 CIDR')
        return v

    @validator('method')
    def method_must_be_a_valid_HTTP_method(cls, v):
        if not v in VALID_HTTP_METHODS:
            raise HTTPException(status_code=400,
                                detail='method must be in %s' %
                                VALID_HTTP_METHODS)
        return v

    @validator('ip_version')
    def ip_version_must_be_4_or_6(cls, v):
        if v not in [4, 6]:
            raise HTTPException(status_code=400,
                                detail='ip_version must be 4 or 6')
        return v


def read_config_from_local_file(filepath: str):
    global DEFAULT_POLICIES, DEBUG
    logger.info('reading configuration from file://%s', filepath)
    if os.path.exists(filepath):
        with open(filepath) as cf:
            try:
                cf_obj = yaml.safe_load(cf)
                DEFAULT_POLICIES = cf_obj['policies']
                DEBUG = cf_obj['debug']
                if DEBUG:
                    logger.setLevel(logging.DEBUG)
            except Exception as error:
                logger.error("Can not load config.yaml file")


def read_config_from_url(fileurl: str):
    global DEFAULT_POLICIES, DEBUG
    logger.info('reading configuration from %s', fileurl)
    try:
        with urllibrequest.urlopen(fileurl) as cf:
            cf_obj = yaml.safe_load(cf)
            DEFAULT_POLICIES = cf_obj['policies']
            DEBUG = cf_obj['debug']
            if DEBUG:
                logger.setLevel(logging.DEBUG)
    except Exception as error:
        logger.error('Error retrieving config file from: %s: %s', fileurl,
                     error)
        read_config_from_local_file(DEFAULT_CONFIG_FILE)


def load_config():
    cf_path: str = os.getenv('CONFIG_FILE', DEFAULT_CONFIG_FILE)
    log_level: str = os.getenv('LOG_LEVEL', logging_config.DEFAULT_LOG_LEVEL)
    if log_level in logging._nameToLevel:
        logger.info('setting logging level to: %s', log_level)
        logger.setLevel(log_level)
    else:
        raise ValueError('Configuration error: LOG_LEVEL must be in: %s',
                         logging._nameToLevel.keys())
    if isinstance(validators.url(cf_path), validators.ValidationFailure):
        read_config_from_local_file(cf_path)
    else:
        read_config_from_url(cf_path)
    load_policies()


def get_policy_hash(policy: dict):
    return "%d-%s-%s" % (policy['id'], policy['src_cidr'], policy['method'])


def load_policies():
    global policies, last_id
    for policy in DEFAULT_POLICIES:
        policy['repeated'] = {}
        if policy['id'] > last_id:
            last_id = policy['id']
        policies[get_policy_hash(policy)] = policy


app = FastAPI(title='ViaUATEndpoint Application',
              description='''
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
              })
app.mount('/static', StaticFiles(directory='static', html=True), name='static')


@app.on_event('startup')
async def startup_event():
    load_config()


def get_policy_by_id(id: int):
    for policy in policies.values():
        if policy['id'] == id:
            return policy
    return None


def zero_out_runs(policy_hash: str):
    logger.info('reached end of run scripts.. zeroing our repeat counts.')
    policies[policy_hash]['repeated'] = {}


def run_direct_response(script, request, response):
    content: str = script['direct_response_body']
    if 'direct_response_body_encoding' in script:
        if script['direct_response_body_encoding'] == 'BASE64':
            content = base64.decode(script['direct_response_body'])
    return Response(content=content,
                    status_code=script['direct_response_status_code'],
                    media_type=script['direct_response_mime_type'],
                    headers=response.headers)


def run_redirect(script, request, response):
    redirect_status_code = 307
    if 'redirect_status_code' in script:
        redirect_status_code = script['redirect_status_code']
    response.headers['location'] = urllibparse.quote(
        script['redirect_url'], safe=":/%#?=@[]!$&'()*+,;")
    return Response(content=None,
                    status_code=redirect_status_code,
                    headers=response.headers)


def run_serve_local(script, request, response):
    return FileResponse(script['serve_local_file_path'],
                        headers=response.headers)


def run_script(script, request, response):
    initial_timestamp = time.time()
    logger.debug('running script %s at %s', json.dumps(script),
                 initial_timestamp)
    if script['delay_ms'] > 0:
        logger.info('apply delay: %d ms', script['delay_ms'])
        time.sleep((script['delay_ms'] / 1000))
    if 'inject_headers' in script:
        for header in script['inject_headers']:
            response.headers[header] = script['inject_headers'][header]
    # return policy matched response
    if script['action'] == 'direct_response':
        return run_direct_response(script, request, response)
    if script['action'] == 'redirect':
        return run_redirect(script, request, response)
    if script['action'] == 'serve_local':
        return run_serve_local(script, request, response)
    return Response(content='invalid action in run script',
                    status_code=400,
                    media_type='text/plain')


def get_client_ip_match(client_ips):
    client_match_policies = {'ALL': [], 'CIDR': {'hosts': 0, 'hashes': []}}
    for policy_hash in policies:
        policy = policies[policy_hash]
        if policy['src_cidr'] == 'ALL':
            logger.debug('client IP matched ALL policy: %s', policy_hash)
            client_match_policies['ALL'].append(policy_hash)
        else:
            for client in client_ips:
                if client and policy['ip_version'] == 4:
                    try:
                        network = ipaddress.IPv4Network(policy['src_cidr'])
                        if ipaddress.IPv4Address(client) in network:
                            logger.debug(
                                'client IPv4: %s matched policy CIDR: %s',
                                client, policy['src_cidr'])
                            if client_match_policies['CIDR']['hosts'] > 0:
                                if network.num_addresses < client_match_policies[
                                        'CIDR']['hosts']:
                                    client_match_policies['CIDR'][
                                        'hosts'] = network.num_addresses
                                    client_match_policies['CIDR']['hashes'] = [
                                        policy_hash
                                    ]
                                elif network.num_addresses == client_match_policies[
                                        'CIDR']['hosts']:
                                    client_match_policies['CIDR'][
                                        'hashes'].append(policy_hash)
                            else:
                                client_match_policies['CIDR'][
                                    'hosts'] = network.num_addresses
                                client_match_policies['CIDR']['hashes'] = [
                                    policy_hash
                                ]
                    except:
                        pass
                elif client and policy['ip_version'] == 6:
                    try:
                        network = ipaddress.IPv6Network(policy['src_cidr'])
                        if ipaddress.IPv6Address(client) in network:
                            logger.debug(
                                'client IPv6: %s matched policy CIDR: %s',
                                client, policy['src_cidr'])
                            if client_match_policies['CIDR']['hosts'] > 0:
                                if network.num_addresses < client_match_policies[
                                        'CIDR']['hosts']:
                                    client_match_policies['CIDR'][
                                        'hosts'] = network.num_addresses
                                    client_match_policies['CIDR']['hashes'] = [
                                        policy_hash
                                    ]
                                elif network.num_addresses == client_match_policies[
                                        'CIDR']['hosts']:
                                    client_match_policies['CIDR'][
                                        'hashes'].append(policy_hash)
                            else:
                                client_match_policies['CIDR'][
                                    'hosts'] = network.num_addresses
                                client_match_policies['CIDR']['hashes'] = [
                                    policy_hash
                                ]
                    except:
                        pass
    if client_match_policies['CIDR']['hosts'] > 0:
        return client_match_policies['CIDR']['hashes']
    else:
        return client_match_policies['ALL']


def get_matched_policy_hash(request, policy_hashes):
    most_specific_policy_hash = None
    most_specific_policy_match_score = 0
    for policy_hash in policy_hashes:
        policy_match_score = 0
        policy = policies[policy_hash]
        # Affirm header
        header_match = False
        if 'headers' in policy and policy['headers']:
            for header in policy['headers']:
                header_name = list(header.keys())[0]
                header_match_value = header[header_name]
                for header in request.headers.raw:
                    logger.debug(
                        'attempting policy match on client request header: %s',
                        header)
                    if header_name.lower() == header[0].lower():
                        if header_match_value == 'any':
                            logger.debug('header: %s matched any', header_name)
                            header_match = True
                            policy_match_score = policy_match_score + 2
                        elif header_match_value == header[1]:
                            logger.debug('header: %s matched value exactly',
                                         header_name)
                            header_match = True
                            policy_match_score = policy_match_score + 3
                        else:
                            try:
                                p = re.compile(header_match_value)
                                if p.match(header[1]):
                                    logger.debug('header: %s match regex',
                                                 header_name)
                                    header_match = True
                                    policy_match_score = policy_match_score + 3
                            except:
                                pass
        else:
            # No match critera for headers, so match all..
            header_match = True
        # Affirm method
        method_match = False
        if policy['method'] == 'ALL':
            method_match = True
            policy_match_score = policy_match_score + 1
        elif policy['method'] == request.method:
            method_match = True
            policy_match_score = policy_match_score + 2
        else:
            method_match = False
        # Affirm path regex
        path_regex_match = False
        if policy['path_re_match'] == 'ALL':
            path_regex_match = True
            policy_match_score = policy_match_score + 1
        else:
            logging.debug('trying path regex match: %s for %s',
                          policy['path_re_match'], request.url.path)
            if policy['path_re_match']:
                try:
                    p = re.compile(policy['path_re_match'])
                    if p.match(request.url.path):
                        path_regex_match = True
                        policy_match_score = policy_match_score + 2
                except:
                    pass
        if header_match and method_match and path_regex_match:
            logger.debug('policy with hash: %s has a match score of %d',
                         policy_hash, policy_match_score)
            if policy_match_score > most_specific_policy_match_score:
                most_specific_policy_match_score = policy_match_score
                most_specific_policy_hash = policy_hash
    logger.debug('policy rule most specific match was: %s with score: %d',
                 most_specific_policy_hash, most_specific_policy_match_score)
    return most_specific_policy_hash


def apply_policy(client_ips, request, response):
    # Find most specific client IP matching
    client_matched_policy_hashes = get_client_ip_match(client_ips)
    # From matching client IP, find policy attribute matching
    policy_match_hash = get_matched_policy_hash(request,
                                                client_matched_policy_hashes)
    policy = policies[policy_match_hash]
    if policy:
        # If matched run reply_scripts
        logger.debug("%s - matched policy: %s", request.url.path,
                     policy_match_hash)
        script_count = len(policies[policy_match_hash]['reply_scripts'])
        for i, script in enumerate(
                policies[policy_match_hash]['reply_scripts']):
            script_hash = str(i)
            if script['repeat'] == 0:
                # run a always matching reply_script
                logger.info("running continue output script")
                return run_script(script, request, response)
            else:
                # keep runtime repeat count state
                if script_hash not in policies[policy_match_hash]['repeated']:
                    policies[policy_match_hash]['repeated'][script_hash] = 0
                policies[policy_match_hash]['repeated'][script_hash] = (
                    policies[policy_match_hash]['repeated'][script_hash] + 1)
                if policies[policy_match_hash]['repeated'][
                        script_hash] <= script['repeat']:
                    logger.info(
                        "running script count %d of %d" %
                        (policies[policy_match_hash]['repeated'][script_hash],
                         script['repeat']))
                    if (
                        (i + 1) == script_count
                    ) and (policies[policy_match_hash]['repeated'][script_hash]
                           == script['repeat']):
                        # if this is the last run_script to run and it has
                        # reached it's final count, reset all counts an
                        # start over with new requests.
                        zero_out_runs(policy_match_hash)
                    return run_script(script, request, response)
                else:
                    continue
    else:
        logger.error('request did not match any policy')
        return Response(content='no policy matched',
                        status_code=400,
                        media_type='text/plain')


@app.get('/logging/', response_class=JSONResponse)
async def set_level(level: str = 'INFO'):
    if level:
        if level in logging._nameToLevel:
            logger.warning('setting log level to: %s', level)
            logger.setLevel(logging._nameToLevel[level])
        else:
            raise HTTPException(status_code=400,
                                detail='Invalid level: %s' % level)
    else:
        level = logger.getEffectiveLevel()
    return Response(content=json.dumps({'log_level': level}), status_code=200)


@app.get('/policies/',
         response_model=List[Policy],
         response_class=JSONResponse)
async def get_policies():
    return list(policies.values())


@app.get('/policies/{id}', response_model=Policy, response_class=JSONResponse)
async def get_policies(id: int):
    policy = get_policy_by_id(id)
    if policy:
        return policy
    else:
        raise HTTPException(status_code=404)


@app.post('/policies/',
          response_model=List[Policy],
          response_class=JSONResponse)
async def create_policy(policy: PolicyCreate):
    global last_id
    last_id = last_id + 1
    id = last_id
    policy_hash = "%s-%s-%s-%s" % (policy.src_cidr, policy.method,
                                   policy.header,
                                   urllibparse.unquote(policy.path_re_match))
    reply_scripts = []
    for rs in policy.reply_scripts:
        rs = {
            'delay_ms': rs.delay_ms,
            'repeat': rs.repeat,
            'status_code': rs.status_code,
            'mime_type': rs.mime_type,
            'body': rs.body,
            'body_encoding': rs.body_encoding
        }
        reply_scripts.append(rs)
    policy_dict = {
        'id': id,
        'src_cidr': policy.src_cidr,
        'method': policy.method,
        'header': policy.header,
        'path_re_match': urllibparse.unquote(policy.path_re_match),
        'ip_version': policy.ip_version,
        'reply_scripts': reply_scripts
    }
    if policy_hash in policies:
        raise HTTPException(status_code=409,
                            detail='Policy with same match criteria exists.')
    else:
        policies[policy_hash] = policy_dict
    return list(policies.values())


@app.delete('/policies/{id}',
            response_model=List[Policy],
            response_class=JSONResponse)
async def delete_policy(id: int):
    policy = get_policy_by_id(id)
    if policy:
        policy_hash = "%s-%s-%s-%s" % (policy['src_cidr'], policy['method'],
                                       policy['header'],
                                       policy['path_re_match'])
        if policy_hash in policies.keys():
            del policies[policy_hash]
    else:
        raise HTTPException(status_code=404)
    return list(policies.values())


def resolve_xff_header(val: str):
    val = val.decode('utf-8')
    if ', ' in val:
        return re.split(', ', val)
    else:
        return [val]


@app.get('/{path_value:path}')
async def get_response(path_value: str, request: Request, response: Response):
    client_ips = [request.client.host]
    x = 'x-forwarded-for'.encode('utf-8')
    for header in request.headers.raw:
        if header[0].lower() == x:
            for ip in resolve_xff_header(header[1]):
                if ip not in client_ips:
                    client_ips.append(ip)
    logger.debug('finding policy for client request from %s', client_ips)
    return apply_policy(client_ips, request, response)


@app.post('/{path_value:path}')
async def post_response(path_value: str, request: Request, response: Response):
    client_host = request.client.host
    origin_ip = None
    forward_ip = None
    x = 'x-forwarded-for'.encode('utf-8')
    for header in request.headers.raw:
        if header[0].lower() == x:
            origin_ip, forward_ip = resolve_xff_header(header[1])
    return apply_policy([origin_ip, forward_ip, client_host], request,
                        response)


@app.put('/{path_value:path}')
async def put_response(path_value: str, request: Request, response: Response):
    client_host = request.client.host
    origin_ip = None
    forward_ip = None
    x = 'x-forwarded-for'.encode('utf-8')
    for header in request.headers.raw:
        if header[0].lower() == x:
            origin_ip, forward_ip = resolve_xff_header(header[1])
    return apply_policy([origin_ip, forward_ip, client_host], request,
                        response)


@app.patch('/{path_value:path}')
async def patch_response(path_value: str, request: Request,
                         response: Response):
    client_host = request.client.host
    origin_ip = None
    forward_ip = None
    x = 'x-forwarded-for'.encode('utf-8')
    for header in request.headers.raw:
        if header[0].lower() == x:
            origin_ip, forward_ip = resolve_xff_header(header[1])
    return apply_policy([origin_ip, forward_ip, client_host], request,
                        response)


@app.head('/{path_value:path}')
async def head_response(path_value: str, request: Request, response: Response):
    client_host = request.client.host
    origin_ip = None
    forward_ip = None
    x = 'x-forwarded-for'.encode('utf-8')
    for header in request.headers.raw:
        if header[0].lower() == x:
            origin_ip, forward_ip = resolve_xff_header(header[1])
    return apply_policy([origin_ip, forward_ip, client_host], request,
                        response)


@app.delete('/{path_value:path}')
async def delete_response(path_value: str, request: Request,
                          response: Response):
    client_host = request.client.host
    origin_ip = None
    forward_ip = None
    x = 'x-forwarded-for'.encode('utf-8')
    for header in request.headers.raw:
        if header[0].lower() == x:
            origin_ip, forward_ip = resolve_xff_header(header[1])
    return apply_policy([origin_ip, forward_ip, client_host], request,
                        response)


@app.options('/{path_value:path}')
async def options_response(path_value: str, request: Request,
                           response: Response):
    client_host = request.client.host
    origin_ip = None
    forward_ip = None
    x = 'x-forwarded-for'.encode('utf-8')
    for header in request.headers.raw:
        if header[0].lower() == x:
            origin_ip, forward_ip = resolve_xff_header(header[1])
    return apply_policy([origin_ip, forward_ip, client_host], request,
                        response)
