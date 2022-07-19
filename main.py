# -*- coding: utf-8 -*-

# main entry point for ViaUATEndpoint

from ast import Delete
import ipaddress
import json
import logging
import os
import re
import time
import urllib
import validators
import yaml

from typing import Optional, List, Union
from enum import Enum

from fastapi import FastAPI, Request, Response, Path, Depends, Query, HTTPException
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

DEFAULT_CONFIG_FILE = "%s/config.yaml" % os.path.dirname(os.path.realpath(__file__))
DEFAULT_POLICIES = [
    {
        'src_cidr': 'ALL',
        'path_re_match': 'ALL',
        'method': 'ALL',
        'header': 'NONE',
        'ip_version': 4,
        'reply_script': [
            {
                'delay_ms': 0,
                'status_code': 200,
                'mime_type': 'application/json',
                'body': '{}',
                'body_encoding': 'NONE'
            }
        ]
    }
]
DEBUG = False

policies = {}

logging.config.fileConfig('logging.conf', disable_existing_loggers=False)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class RunScript(BaseModel):
    delay_ms: Union[int, None] = Field(
        default=0,
        title='Delay in milliseconds',
        description='Delay the response to this request by this many milliseconds'
    )
    repeat: Union[int, None] = Field(
        default=0,
        title='Repeat script',
        description='How many times to repeat this script step before progressing to the next'
    )
    status_code: Union[int, None] = Field(
        default=200,
        title='HTTP response status code',
        description='The HTTP status code to return'
    )
    mime_type: Union[str,None] = Field(
        default='application/json',
        title='MIME type to return',
        description='MIME type of the return body'
    )
    body: Union[str, None] = Field(
        default='{}',
        title='Body content',
        description='Response body content'
    )
    body_encoding: Union[str, None] = Field(
        default='NONE',
        title='Body content encoding',
        description='Either do not encode the body content (NONE) or else base64encode it (BASE64)'
    )

class Policy(BaseModel):
    src_cidr: Union[str, None] = Field(
        default='ALL',
        title='Client CIDR',
        description='The IPv4 or IPv6 CIDR to match the client request'
    )
    method: Union[str, None] = Field(
        default='ALL',
        title='HTTP Request Method',
        description='The HTTP request method to match the request'
    )
    header: Union[str, None] = Field(
        default='NONE',
        title='HTTP header to match',
        description='An HTTP header to match for the request'
    )
    path_re_match: Union[str, None] = Field(
        default='ALL',
        title='Regular Expression',
        description='HTTP path regular expression match for the request'
    )
    ip_version: Union[int, None] = Field(
        default=4,
        title='IP Version',
        description='The IP version, 4 or 6, to match the request'
    )
    reply_scripts: List[RunScript] = DEFAULT_POLICIES


def read_config_from_local_file(filepath):
    global DEFAULT_POLICIES, DEBUG
    logger.debug('reading configuration from file://%s', filepath)
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


def read_config_from_url(fileurl):
    global DEFAULT_POLICIES, DEBUG
    logger.debug('reading configuration from %s', fileurl)
    try:
        with urllib.request.urlopen(fileurl) as cf:
            cf_obj = yaml.safe_load(cf)
            DEFAULT_POLICIES = cf_obj['policies']
            DEBUG = cf_obj['debug']
            if DEBUG:
                logger.setLevel(logging.DEBUG)
    except Exception as error:
        read_config_from_local_file(DEFAULT_CONFIG_FILE)


def load_config():
    cf_path = os.getenv(
        'CONFIG_FILE',
        DEFAULT_CONFIG_FILE
    )
    if isinstance(validators.url(cf_path), validators.ValidationFailure):
        read_config_from_local_file(cf_path)
    else:
        read_config_from_url(cf_path)
    load_policies()


def get_policy_hash(policy):
    return "%s-%s-%s-%s" % (
        policy['src_cidr'],
        policy['method'],
        policy['header'],
        policy['path_re_match']
    )


def load_policies():
    global policies
    for policy in DEFAULT_POLICIES:
        policy['repeated'] = {}
        policies[get_policy_hash(policy)] = policy


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

load_config()

@app.on_event('startup')
async def startup_event():
    load_config()


def run_script(script, request):
    initial_timestamp = time.time()
    logger.debug('running script %s at %s', json.dumps(script), initial_timestamp)
    debug_body = {
        'initial_timestamp': initial_timestamp,
        'delayed_timestamp': initial_timestamp,
        'status_code': DEFAULT_POLICIES[0]['reply_scripts'][0]['status_code'],
        'mime_type': DEFAULT_POLICIES[0]['reply_scripts'][0]['mime_type']
    }
    if script['delay_ms'] > 0:
        logger.info('apply delay: %d ms', script['delay_ms'])
        time.sleep((script['delay_ms']/1000))
    debug_body['delayed_timestamp'] = time.time()
    debug_body['status_code'] = script['status_code']
    debug_body['mime_type'] = script['mime_type']
    debug_body['client_ip'] = request.client.host
    if DEBUG:
        # return DEBUG response
        return Response(
            content=json.dumps(debug_body, indent=4, sort_keys=False),
            status_code=script['status_code'],
            media_type=script['mime_type'],
        )
    else:
        # return policy matched response
        logging.debug('response status_code: %d', script['status_code'])
        logging.debug('response mime type: %s', script['mime_type'])
        logging.debug('response body: %s', script['body'])
        return Response(
            content=script['body'],
            status_code=script['status_code'],
            media_type=script['mime_type']
        )


def zero_out_runs(policy_hash):
    logger.info('reached end of run scripts.. zeroing our repeat counts.')
    policies[policy_hash]['repeated'] = {}


def apply_policy(client_ips, request):
    # Find client IP matching
    client_matched_policies = []
    for policy_hash in policies:
        policy = policies[policy_hash]
        if policy['src_cidr'] == 'ALL':
            client_matched_policies.append(policy_hash)
        else:
            for client in client_ips:
                if client and policy['ip_version'] == 4:
                        try:
                            if ipaddress.IPv4Address(client) in ipaddress.IPv4Network(policy['src_cidr']):
                                client_matched_policies.append(policy_hash)
                        except:
                            pass
                elif client and policy['ip_version'] == 6:
                    try:
                        if ipaddress.IPv6Address(client) in ipaddress.IPv6Network(policy['src_cidr']):
                            client_matched_policies.append(policy_hash)
                    except:
                        pass
    # From matching client IP, find policy attribute matching
    for policy_hash in client_matched_policies:
        policy = policies[policy_hash]
        # Affirm header
        header_match = False
        if policy['header'] == 'NONE':
            header_match = True
        else :
            for header in request.headers.raw:
                if header[0].lower() == policy['header']:
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
        if header_match and method_match and path_regex_match:
            # If matched run reply_scripts
            logger.debug("%s - matched policy: %s",
                request.url.path, policy_hash)
            script_count = len(policies[policy_hash]['reply_scripts'])
            for i, script in enumerate(policies[policy_hash]['reply_scripts']):
                script_hash = str(i)
                if script['repeat'] == 0:
                    # run a always matching reply_script
                    logger.info("running continue output script")
                    return run_script(script, request)
                else:
                    # keep runtime repeat count state
                    if script_hash not in policies[policy_hash]['repeated']:
                        policies[policy_hash]['repeated'][script_hash] = 0
                    policies[policy_hash]['repeated'][script_hash] = (
                            policies[policy_hash]['repeated'][script_hash] + 1)
                    if policies[policy_hash]['repeated'][script_hash] <= script['repeat']:
                        logger.info("running script count %d of %d" % (
                            policies[policy_hash]['repeated'][script_hash], script['repeat']))
                        if ((i + 1) == script_count) and (
                             policies[policy_hash]['repeated'][script_hash] == script['repeat']):
                            # if this is the last run_script to run and it has
                            # reached it's final count, reset all counts an
                            # start over with new requests.
                            zero_out_runs(policy_hash)
                        return run_script(script, request)
                    else:
                        continue
        else:
            continue


@app.get('/configs/', response_model=List[Policy], response_class=JSONResponse)
async def get_policies():
    return list(policies.values())


@app.post('/configs/', response_model=List[Policy], response_class=JSONResponse)
async def create_policy(policy: Policy):
    policy_hash =  "%s-%s-%s-%s" % (
        policy.src_cidr,
        policy.method,
        policy.header,
        policy.path_re_match
    )
    reply_scripts = []
    for rs in policy.reply_scripts:
        reply_scripts.append(dict(rs))
    policy_dict = dict(policy)
    policy_dict['reply_scripts'] = reply_scripts
    if policy_hash in policies:
        raise HTTPException(status_code=409,
            detail='Policy with same match criteria exists.')
    else:
        policies[policy_hash] = policy
    return list(policies.values())


@app.delete('/configs/', response_model=List[Policy], response_class=JSONResponse)
async def delete_policy(
        src_cidr: str = Query(
            description='''Client source CIDR (IPv4 of IPv6) to search for
            a match to delete.''',
            example='ANY or 192.168.12.0/24',
            default='ANY'
        ),
        method: str = Query(
                description='The HTTP method to search for a match to delete.',
                example='ALL, GET, POST, PUT, PATCH, HEAD, DELETE',
                default='ALL'
        ),
        header: str = Query(
            description='HTTP header to search for a match to delete',
            example='NONE or x-auth-key',
            default='NONE'
        ),
        path_re_match = Query(
            description='Query path regular expression to match to delete',
            example='ALL or "^/get/.*$"',
            default='ALL'
        )):
    policy_hash =  "%s-%s-%s-%s" % (
        src_cidr,
        method,
        header,
        urllib.parse.unquote(path_re_match)
    )
    if policy_hash in policies.keys():
        del policies[policy_hash]
    return list(policies.values())




@app.get('/{path_name:path}')
async def get_response(path_name: str, request: Request, response: Response):
    client_host = request.client.host
    origin_ip = None
    forward_ip = None
    x = 'x-forwarded-for'.encode('utf-8')
    for header in request.headers.raw:
        if header[0].lower() == x:
            origin_ip, forward_ip = re.split(', ', header[1].decode('utf-8'))
    return apply_policy([origin_ip, forward_ip, client_host], request)


@app.post('/{path_name:path}')
async def post_response(path_value: str, request: Request, response: Response):
    client_host = request.client.host
    origin_ip = None
    forward_ip = None
    x = 'x-forwarded-for'.encode('utf-8')
    for header in request.headers.raw:
        if header[0].lower() == x:
            origin_ip, forward_ip = re.split(', ', header[1].decode('utf-8'))
    return apply_policy([origin_ip, forward_ip, client_host], request)


@app.put('/{path_value:path}')
async def put_response(path_value: str, request: Request, response: Response):
    client_host = request.client.host
    origin_ip = None
    forward_ip = None
    x = 'x-forwarded-for'.encode('utf-8')
    for header in request.headers.raw:
        if header[0].lower() == x:
            origin_ip, forward_ip = re.split(', ', header[1].decode('utf-8'))
    return apply_policy([origin_ip, forward_ip, client_host], request)


@app.patch('/{path_value:path}')
async def patch_response(path_value: str, request: Request, response: Response):
    client_host = request.client.host
    origin_ip = None
    forward_ip = None
    x = 'x-forwarded-for'.encode('utf-8')
    for header in request.headers.raw:
        if header[0].lower() == x:
            origin_ip, forward_ip = re.split(', ', header[1].decode('utf-8'))
    return apply_policy([origin_ip, forward_ip, client_host], request)


@app.head('/{path_value:path}')
async def head_response(path_value: str, request: Request, response: Response):
    client_host = request.client.host
    origin_ip = None
    forward_ip = None
    x = 'x-forwarded-for'.encode('utf-8')
    for header in request.headers.raw:
        if header[0].lower() == x:
            origin_ip, forward_ip = re.split(', ', header[1].decode('utf-8'))
    return apply_policy([origin_ip, forward_ip, client_host], request)


@app.delete('/{path_value:path}')
async def delete_response(path_value: str, request: Request, response: Response):
    client_host = request.client.host
    origin_ip = None
    forward_ip = None
    x = 'x-forwarded-for'.encode('utf-8')
    for header in request.headers.raw:
        if header[0].lower() == x:
            origin_ip, forward_ip = re.split(', ', header[1].decode('utf-8'))
    return apply_policy([origin_ip, forward_ip, client_host], request)
