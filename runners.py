import base64
import json
import logging
import time
import httpx
import urllib.parse as urllibparse

from starlette.background import BackgroundTask
from fastapi import Response
from fastapi.responses import FileResponse, StreamingResponse

logger = logging.getLogger("viauatdemo")


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
    if script['action'] == 'proxy':
        return proxy(script, request, response)
    if script['action'] == 'dump':
        return dump(script, request, response)
    return Response(content='invalid action in run script',
                    status_code=400,
                    media_type='text/plain')


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


def proxy(script, request, response):
    client = httpx.Client(verify=False)
    headers = dict(request.headers)
    proxy_url = urllibparse.urlsplit(script['proxy_url'])
    headers['host'] = proxy_url.netloc
    req = client.build_request(
        request.method,
        script['proxy_url'])
    rep = client.send(req)
    return StreamingResponse(
        rep.aiter_text())


def dump(script, request, response):
    dump_dict = {
        'url': str(request.url),
        'method': request.method,
        'headers': dict(request.headers),
        'query': dict(request.query_params),
        'clientip': request.client.host,
        'cookies': dict(request.cookies)
    }
    return Response(content=json.dumps(dump_dict),
                    status_code=200, media_type='application/json')


def zero_out_runs(policy_hash: str, policies):
    logger.info('reached end of run scripts.. zeroing our repeat counts.')
    policies[policy_hash]['repeated'] = {}


def run_reply_scripts(policy_match_hash, policies, request, response):
    script_count = len(policies[policy_match_hash]['reply_scripts'])
    for i, script in enumerate(
            policies[policy_match_hash]['reply_scripts']):
        script_hash = str(i)
        if 'repeat' not in script:
            script['repeat'] = 0
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
                    zero_out_runs(policy_match_hash, policies)
                return run_script(script, request, response)
            else:
                continue
