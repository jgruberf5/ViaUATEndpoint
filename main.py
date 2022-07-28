# -*- coding: utf-8 -*-

# main entry point for ViaUATEndpoint
import json
import logging
import os

import logging_config
import const
import config
import runners
import utils

from timer import Timer

import urllib.parse as urllibparse
import validators

from typing import Mapping, List, Union, Any
from enum import Enum

from fastapi import FastAPI, Request, Response, Path, Depends, Query, HTTPException
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
from starlette.background import BackgroundTask
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, FilePath, ValidationError, validator

from const import DEFAULT_CONFIG_FILE, DEFAULT_POLICIES, VALID_HTTP_STATUS_CODES, VALID_HTTP_METHODS, ACTIONS

logger = logging_config.init_logging()

last_id: int = 0
policies: dict = {}
reload_timer: Timer = None

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
        'What action to take: direct_response, redirect, serve_local, or proxy')
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
    proxy_url: Union[str, None] = Field(
        default='NONE',
        title='Proxy URL',
        description='Proxy a request to the URL and return its content to the request'
    )

    @validator('action')
    def action_needs_to_be_in_supported_actions(cls, v):
        if v not in ACTIONS:
            raise HTTPException(status_code=400,
                                detail='action must be in %s' % ACTIONS)
        return v

    @validator('direct_response_status_code')
    def status_code_must_be_in_list(cls, v):
        if v not in VALID_HTTP_STATUS_CODES:
            raise HTTPException(
                status_code=400,
                detail='direct_response_status_code must be a valid HTTP status code')
        return v

    @validator('direct_response_mime_type')
    def mime_type_must_include_category_and_type(cls, v):
        if ('/' not in v) or (v.find('/') < 1):
            raise HTTPException(
                status_code=400,
                detail='direct_response_mime_type must include a category and type')
        return v

    @validator('direct_response_body_encoding')
    def body_encoding_must_be_none_or_base64(cls, v):
        if v not in ['NONE', 'BASE64']:
            raise HTTPException(status_code=400,
                                detail='direct_response_body_encoding must be NONE or BASE64')
        return v

    @validator('redirect_status_code')
    def redirect_status_code_must_be_in_list(cls, v):
        if v not in [301, 302, 307]:
            raise HTTPException(
                status_code=400,
                detail='redirect_status_code should be 301,302 or 307')
        return v

    @validator('proxy_url')
    def proxy_url_must_be_valid_url(cls, v):
        if not isinstance(validators.url(v), validators.ValidationFailure):
            raise HTTPException(
                status_code=400,
                detail='proxy_url must be a valid URL'
            )

class Policy(BaseModel):
    id: Union[int, None] = Field(
        default=0,
        title='Policy Id',
        description='Service generated reference to policy')
    ip_version: Union[int, None] = Field(
        default=4,
        title='IP Version',
        description='The IP version, 4 or 6, to match the request')
    src_cidr: Union[str, None] = Field(
        default='ALL',
        title='Client CIDR',
        description='The IPv4 or IPv6 CIDR to match the client request')
    env: Union[List[Mapping[str, str]], None] = Field (
        default=[],
        title='ENV Variables',
        description='Environment variables to match'
    )
    env_match_policy: Union[str, None] = Field(
        default='AND',
        title='ENV Matching Policy',
        description='How to match variables can be AND, OR, or number to match as a string'
    )
    method: Union[str, None] = Field(
        default='ALL',
        title='HTTP Request Method',
        description='The HTTP request method to match the request')
    headers: Union[List[Mapping[str, str]], None] = Field(
        default=[],
        title='HTTP headers and values to match',
        description='List of HTTP headers and values to match for the request')
    header_match_policy: Union[str, None] = Field(
        default='AND',
        title='Header Matching Policy',
        description='How to match headers can be AND, OR, or number to match as a string'
    )
    path_re_match: Union[str, None] = Field(
        default='ALL',
        title='Regular Expression',
        description='HTTP path regular expression match for the request')
    query: Union[List[Mapping[str, str]], None] = Field (
        default=[],
        title='HTTP Query Variables',
        description='HTTP query variables to match'
    )
    query_match_policy: Union[str, None] = Field(
        default='AND',
        title='Query Matching Policy',
        description='How to match HTTP query variables can be AND, OR, or number to match as a string'
    )
    day_of_week: Union[str, None] = Field(
        default='ANY',
        title='Day of Week',
        description='Day of the week to match policy can be ANY or [SU][M][T][W][R][F][SA] i.e. SUM for Sunday and Monday'
    )
    start_time: Union[str, None] = Field(
        default=None,
        title='Start Time',
        description='Star time in HH:MM:ss 24 hour format',
    )
    stop_time: Union[str, None] = Field(
        default=None,
        title='Stop Time',
        description='Stop time in HH:MM:ss 24 hour format',
    )
    reply_scripts: List[RunScript] = DEFAULT_POLICIES[0]['reply_scripts']


class PolicyCreate(BaseModel):
    src_cidr: Union[str, None] = Field(
        default='ALL',
        title='Client CIDR',
        description='The IPv4 or IPv6 CIDR to match the client request')
    ip_version: Union[int, None] = Field(
        default=4,
        title='IP Version',
        description='The IP version, 4 or 6, to match the request')
    env: Union[List[Mapping[str, str]], None] = Field (
        default=[],
        title='ENV Variables',
        description='Environment variables to match'
    )
    env_match_policy: Union[str, None] = Field(
        default='AND',
        title='ENV Matching Policy',
        description='How to match variables can be AND, OR, or number to match as a string'
    )
    method: Union[str, None] = Field(
        default='ALL',
        title='HTTP Request Method',
        description='The HTTP request method to match the request')
    headers: Union[List[Mapping[str, str]], None] = Field(
        default='NONE',
        title='HTTP headers and values to match',
        description='List of HTTP headers and values to match for the request')
    header_match_policy: Union[str, None] = Field(
        default='AND',
        title='Header Matching Policy',
        description='How to match headers can be AND, OR, or number to match as a string'
    )
    path_re_match: Union[str, None] = Field(
        default='ALL',
        title='Regular Expression',
        description='HTTP path regular expression match for the request')
    query: Union[List[Mapping[str, str]], None] = Field (
        default=[],
        title='HTTP Query Variables',
        description='HTTP query variables to match'
    )
    query_match_policy: Union[str, None] = Field(
        default='AND',
        title='Query Matching Policy',
        description='How to match HTTP query variables can be AND, OR, or number to match as a string'
    )
    day_of_week: Union[str, None] = Field(
        default='ANY',
        title='Day of Week',
        description='Day of the week to match policy can be ANY or [SU][M][T][W][R][F][SA] i.e. SUM for Sunday and Monday'
    )
    start_time: Union[str, None] = Field(
        default=None,
        title='Start Time',
        description='Star time in HH:MM:ss 24 hour format',
    )
    stop_time: Union[str, None] = Field(
        default=None,
        title='Stop Time',
        description='Stop time in HH:MM:ss 24 hour format',
    )
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

    @validator('header_match_policy')
    def header_match_policy_in_list(cls, v):
        if not v in ['AND', 'OR']:
            try:
                int(v)
            except:
                raise HTTPException(
                    status_code=400,
                    detail='header_match_policy must be AND, OR, or a number as a string')
        return v

    @validator('ip_version')
    def ip_version_must_be_4_or_6(cls, v):
        if v not in [4, 6]:
            raise HTTPException(status_code=400,
                                detail='ip_version must be 4 or 6')
        return v


    @validator('day_of_week')
    def day_of_week_should_have_at_least_one_day(cls, v):
        if not utils.return_days_of_week(v):
            raise HTTPException(
                status_code=400,
                detail='day_of_week must have at least one of %s in it' % const.VALID_DAYS_OF_WEEK)
        return v


    @validator('start_time')
    def start_time_should_be_valid_24_hour_time(cls, v):
        if not utils.is_hhmmss(v):
            raise HTTPException(status_code=400,
                                detail='start_time must be HH:MM:ss')
        return v


    @validator('stop_time')
    def stop_time_should_be_valid_24_hour_time(cls, v):
        if not utils.is_hhmmss(v):
            raise HTTPException(status_code=400,
                                detail='stop_time must be HH:MM:ss')
        return v



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
    if config.RELOAD_TIMER > 0:
        reload_on_time(config.RELOAD_TIMER)


def load_config():
    global last_id, policies
    last_id, policies = config.intialize_config()


def reload_on_time(seconds_between_reload):
    global reload_timer
    if seconds_between_reload > 0:
        if not reload_timer:
            reload_timer = Timer(seconds_between_reload, True, load_config)


def get_policy_by_id(id: int):
    for policy in policies.values():
        if policy['id'] == id:
            return policy
    return None


def apply_policy(request, response):
    # Resolve client IPs to match policy for this request
    client_ips = utils.get_client_ips_for_request(request)
    # Find most specific client IP matching request
    client_matched_policy_hashes = utils.get_client_ip_match(client_ips, policies)
    # Find policy matching client reqeust
    policy_match_hash = utils.get_matched_policy_hash(
        request, client_matched_policy_hashes, policies)
    # Apply matching policy run scripts
    if policy_match_hash:
        policy = policies[policy_match_hash]
        # If matched run reply_scripts
        logger.debug("%s - matched policy: %s", request.url.path,
                    policy_match_hash)
        return runners.run_reply_scripts(policy_match_hash, policies, request, response)
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
    return Response(content=json.dumps({'log_level': level}),
                    status_code=200, media_type='application/json')


@app.get('/config/', response_class=JSONResponse)
async def reload_config_from_file(config_file: str = None, reload_timer: int = 0):
    global last_id, policies
    last_id, policies = config.load_policies(config_file, reload_timer)
    if reload_timer > 0:
        reload_on_time(config.RELOAD_TIMER)
    return Response(content=json.dumps({'config_file': config.CONFIG_FILE}),
                    status_code=200, media_type='application/json')


@app.get('/enviornment/', response_class=JSONResponse)
async def dump_evironment():
    return Response(content=json.dumps(dict(os.environ)),
                    status_code=200,
                    media_type='application/json')


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


@app.get('/{path_value:path}')
async def get_response(path_value: str, request: Request, response: Response):
    return apply_policy(request, response)


@app.post('/{path_value:path}')
async def post_response(path_value: str, request: Request, response: Response):
    return apply_policy(request, response)


@app.put('/{path_value:path}')
async def put_response(path_value: str, request: Request, response: Response):
    return apply_policy(request, response)


@app.patch('/{path_value:path}')
async def patch_response(path_value: str, request: Request,
                         response: Response):
    return apply_policy(request, response)


@app.head('/{path_value:path}')
async def head_response(path_value: str, request: Request, response: Response):
    return apply_policy(request, response)


@app.delete('/{path_value:path}')
async def delete_response(path_value: str, request: Request,
                          response: Response):
    return apply_policy(request, response)


@app.options('/{path_value:path}')
async def options_response(path_value: str, request: Request,
                           response: Response):
    return apply_policy(request, response)
