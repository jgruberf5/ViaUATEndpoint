import ipaddress
import json
import os
import re
import validators

import urllib.parse as urllibparse

from datetime import datetime
from datetime import date
from datetime import time

import logging_config
import const

logger = logging_config.init_logging()


def sub_env_variables(val: str):
    for m in re.findall('\{\{(.*?)\}\}', val):
        env_val = os.getenv(m.strip(), None)
        if env_val:
            val = val.replace('{{%s}}' % m, env_val)
    return val


def resolve_xff_header(val: str):
    val = val.decode('utf-8')
    if ', ' in val:
        return re.split(', ', val)
    else:
        return [val]


def get_client_ips_for_request(request):
    client_ips = [request.client.host]
    x = 'x-forwarded-for'.encode('utf-8')
    for header in request.headers.raw:
        if header[0].lower() == x:
            for ip in resolve_xff_header(header[1]):
                if ip not in client_ips:
                    client_ips.append(ip)
    return client_ips


def is_url(v):
    if isinstance(validators.url(v), validators.ValidationFailure):
        return False
    return True

def is_hhmmss(v):
    p = re.compile('^([0-2])([0-4]):([0-5])([0-9]):([0-5])([0-9])$')
    if p.match(v):
        return True
    return False


def return_days_of_week(daysofweekstr):
    days = []
    for d in const.VALID_DAYS_OF_WEEK:
        if daysofweekstr.find(d) >= 0:
            days.append(d)
    return days


def is_today(daysofweekstr):
    if daysofweekstr.lower() == 'any':
        return True
    days = return_days_of_week(daysofweekstr)
    day = datetime.today().weekday()
    if day == 0 and 'M' in days:
        return True
    if day == 1 and 'T' in days:
        return True
    if day == 2 and 'W' in days:
        return True
    if day == 3 and 'R' in days:
        return True
    if day == 4 and 'F' in days:
        return True
    if day == 5 and 'SA' in days:
        return True
    if day == 6 and 'SU' in days:
        return True
    return False


def is_between_time(start_time, end_time):
    start = time(int(start_time[0:2]), int(start_time[3:5]), int(start_time[6:]))
    end = time(int(end_time[0:2]), int(end_time[3:5]), int(end_time[6:]))
    current = datetime.now().time()
    if start <= current <= end:
        start_dt = datetime.combine(date.today(), start)
        end_dt = datetime.combine(date.today(), end)
        timediff = end_dt - start_dt
        return timediff.total_seconds()
    else:
        return 0


def get_policy_hash(policy: dict):
    return "%d-%s-%s" % (policy['id'], policy['src_cidr'], policy['method'])


def get_client_ip_match(client_ips, policies):
    """
    Qualify this request by its source IP address CIDR: policy src_cidr.

    This is the highest pass of the policies to limit policy processing
    to just a list of policies which match a request client against
    a policy src_cidr.
    """
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
                    except Exception as ex:
                        logger.debug(
                            'IPv4 address: %s had issue testing in network %s: %s',
                            client, policy['src_cidr'], ex)
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
                    except Exception as ex:
                        logger.debug(
                            'IPv6 address: %s had issue testing in network %s: %s',
                            client, policy['src_cidr'], ex)
    if client_match_policies['CIDR']['hosts'] > 0:
        return client_match_policies['CIDR']['hashes']
    else:
        return client_match_policies['ALL']


def get_matched_policy_hash(request, policy_hashes, policies):
    """
    Given a request, match the most specifically defined policy.

    Policies contain match properties for:

        day_of_week:   string of the form [SU][M][T][W][R][F][SA]
                       which is use to match policies to specific
                       days of the week they would apply.

                       i.e. for a policy which runs on Sunday,
                       Tuesday, and Friday, the policy day_of_week
                       would look like SUTF

        time:
           start_time: the start time they policy begins to apply
           stop_time:  the stop time the policy ceases to apply

                       Both times are in 24hr format HH:MM:ss

        env:           the policy would match if a specific environment
                       variable is defined and optionally have its
                       value matched exactly or by regular expression.

                       env is a list of name/value pairs like:

                       VES_IO_SITENAME: ves-io-pa4-par
                       HOSTNAME: '^wwwapp.*'
                       PRODENV: 'ANY'

        headers:       the policy would match if a specific request
                       header is defined and optionally have its
                       value matched exactly or by regular expression.

                       headers is a list of name/value pairs like:

                       Host: www.demo.com
                       User-Agent: '.*Linux.*'
                       X-App-Tester: 'ANY'

        method:        the policy would match if the request method is
                       defined as 'ANY', 'GET', 'POST' 'PUT', 'PATCH',
                       'HEAD', 'OPTIONS', 'DELETE'

        query:         the policy would match if a specific request
                       query variable is present and optionally have its
                       value matched exactly or by regular expression.

                       query is a list of name/value pairs like:

    """
    most_specific_policy_hash = None
    most_specific_policy_match_score = 0

    lowest_timediff_policy_hash = None
    lowest_timediff = 86400
    time_match_score = 0

    for policy_hash in policy_hashes:
        policy_match_score = 0
        policy = policies[policy_hash]
        # day matching
        day_match_score = 0
        day_match = False
        if 'day_of_week' in policy and policy['day_of_week']:
            if policy['day_of_week'].lower() == 'any':
                day_match = True
                day_match_score = 1
            elif is_today(policy['day_of_week']):
                day_match = True
                day_match_score = 2
            else:
                logger.debug('day_of_week %s present in policy, currently false.',
                             policy['day_of_week'])
        else:
            day_match = True
        policy_match_score = policy_match_score + day_match_score
        # time_matching
        time_match = False
        if 'start_time' in policy and policy['start_time'] and \
                         'stop_time' in policy and policy['stop_time']:
            timediff_seconds = is_between_time(policy['start_time'], policy['stop_time'])
            if timediff_seconds:
                logger.debug('start_time: %s stop_time: %s present in %s returned %d seconds difference',
                    policy['start_time'], policy['stop_time'], policy_hash, timediff_seconds)
                time_match = True
                if lowest_timediff_policy_hash:
                    if timediff_seconds < lowest_timediff:
                        lowest_timediff_policy_hash = policy_hash
                        lowest_timediff = timediff_seconds
                        time_match_score = time_match_score + 1
                        logger.debug('policy %s is now the smallest time window with time match score at: %d',
                            policy_hash, time_match_score)
                else:
                    lowest_timediff_policy_hash = policy_hash
                    lowest_timediff = timediff_seconds
                    time_match_score = 1
            else:
                logger.debug(
                    'start_time: %s stop_time: %s present in %s, currently false.',
                    policy['start_time'], policy['stop_time'], policy_hash)
        else:
            time_match = True
        policy_match_score = policy_match_score + time_match_score
        # env matching is present and value
        env_match = False
        if 'env' in policy and policy['env']:
            env_required_to_match = 0
            if 'env_policy_match' not in policy:
                policy['env_policy_match'] = 'and'
            if policy['env_policy_match'].lower() == 'and':
                env_required_to_match = len(policy['env'])
            elif policy['env_policy_match'].lower() == 'or':
                env_required_to_match = 1
            else:
                try:
                    env_required_to_match = int(policy['env_match_policy'])
                except:
                    pass
            if env_required_to_match:
                # logger.debug('need to match at %d envs', env_required_to_match)
                env_match_score = 0
                number_envs_matching = 0
                # we have to interate through them all
                # in case the match with the higher
                # precise matching is latter in the match
                for env in policy['env']:
                    env_name = list(env.keys())[0]
                    env_match_value = env[env_name]
                    if os.getenv(env_name, None):
                        #logger.debug('checking env %s match for %s',
                        #             env, env_match_value)
                        if env_match_value.lower() == 'any':
                            logger.debug('env: %s matched any', env)
                            number_envs_matching = number_envs_matching + 1
                            env_match_score = env_match_score + 1
                        elif env_match_value == os.getenv(env_name):
                            logger.debug('env: %s matched exact', env)
                            number_envs_matching = number_envs_matching + 1
                            env_match_score = env_match_score + 3
                        else:
                            try:
                                p = re.compile(env_match_value)
                                if p.match(os.getenv(env_name)):
                                    logger.debug('env: %s matched regex', env)
                                    number_envs_matching = number_envs_matching + 1
                                    env_match_score = env_match_score + 2
                            except:
                                pass
                    else:
                        logger.debug('env %s in policy not found in environment', env_name)
                if number_envs_matching >= env_required_to_match:
                    env_match = True
                    policy_match_score = policy_match_score + env_match_score
        else:
            # No match critera for env, so match all..
            env_match = True
        # Header matching is presence and value
        header_match = False
        if 'headers' in policy and policy['headers']:
            # If multiple headers are present, all must match.
            headers_required_to_match = 0
            if 'header_match_policy' not in policy:
                policy['header_match_policy'] = 'and'
            if policy['header_match_policy'].lower() == 'and':
                headers_required_to_match = len(policy['headers'])
            elif policy['header_match_policy'].lower() == 'or':
                headers_required_to_match = 1
            else:
                try:
                    headers_required_to_match = int(policy['header_match_policy'])
                except:
                    pass
            if headers_required_to_match:
                # logger.debug('need to match at %d headers', env_required_to_match)
                header_match_scrore = 0
                number_headers_matching = 0
                # avoid looping over and over
                request_headers = request.headers.keys()
                # logger.debug('request headers: %s', request_headers)
                # we have to interate through them all
                # in case the match with the higher
                # precise matching is latter in the match
                for header in policy['headers']:
                    header_name = list(header.keys())[0]
                    header_match_value = header[header_name]
                    found_header = None
                    found_value = None
                    for rh in request_headers:
                        if header_name.lower() == rh.lower():
                            found_header = rh
                            found_value = request.headers.get(found_header)
                    if found_header and found_value:
                        #logger.debug(
                        #    'checking header %s:%s match for %s',
                        #    header_name,
                        #    found_header,
                        #    header_match_value)
                        if header_match_value.lower() == 'any':
                            logger.debug('header: %s matched any', header_name)
                            number_headers_matching = number_headers_matching + 1
                            header_match_scrore = header_match_scrore + 1
                        elif header_match_value == found_value:
                            logger.debug('header: %s matched exact',
                                         header_name)
                            number_headers_matching = number_headers_matching + 1
                            header_match_scrore = header_match_scrore + 3
                        else:
                            try:
                                p = re.compile(header_match_value)
                                if p.match(found_header):
                                    logger.debug('header: %s matched regex', header_name)
                                    number_headers_matching = number_headers_matching + 1
                                    header_match_scrore = header_match_scrore + 2
                            except:
                                pass
                    else:
                        logger.debug(
                            'header %s in policy not found in request', header_name)
                if number_headers_matching >= headers_required_to_match:
                    header_match = True
                    policy_match_score = policy_match_score + header_match_scrore
        else:
            # No match critera for headers, so match all..
            header_match = True
        # Affirm method
        method_match = False
        if 'method' not in policy:
            policy['method'] = 'ANY'
        if policy['method'] == 'ALL' or policy['method'] == 'ANY':
            method_match = True
            policy_match_score = policy_match_score + 1
        elif policy['method'] == request.method:
            method_match = True
            policy_match_score = policy_match_score + 2
        else:
            method_match = False
        # Affirm path regex
        path_regex_match = False
        if 'path_re_match' not in policy:
            policy['path_re_match'] = 'ALL'
        if policy['path_re_match'] == 'ALL':
            path_regex_match = True
            policy_match_score = policy_match_score + 1
        else:
            logger.debug('trying path regex match: %s for %s',
                          policy['path_re_match'], request.url.path)
            if policy['path_re_match']:
                try:
                    p = re.compile(policy['path_re_match'])
                    if p.match(request.url.path):
                        path_regex_match = True
                        policy_match_score = policy_match_score + 2
                except:
                    pass

        # Query variable matching is presence and value
        query_match = False
        if 'query' in policy and policy['query']:
            # If multiple headers are present, all must match.
            query_required_to_match = 0
            if 'query_match_policy' not in policy or \
                    policy['query_match_policy'].lower() == 'and':
                query_required_to_match = len(policy['query'])
            elif policy['query_match_policy'].lower() == 'or':
                query_required_to_match = 1
            else:
                try:
                    query_required_to_match = int(policy['query_match_policy'])
                except:
                    pass
            if query_required_to_match:
                query_match_scrore = 0
                number_query_matching = 0
                # avoid looping over and over
                found_query = urllibparse.parse_qs(str(request.query_params))
                # we have to interate through them all
                # in case the match with the higher
                # precise matching is latter in the match
                for query in policy['query']:
                    query_name = list(query.keys())[0]
                    query_match_value = query[query_name]
                    if query_name in found_query:
                        if query_match_value.lower() == 'any':
                            logger.debug('query: %s matched any', query_name)
                            number_query_matching = number_query_matching + 1
                            query_match_scrore = query_match_scrore + 1
                        elif query_match_value in found_query[query_name]:
                            logger.debug('query: %s matched exact', query_name)
                            number_query_matching = number_query_matching + 1
                            query_match_scrore = query_match_scrore + 3
                        else:
                            try:
                                p = re.compile(query_match_value)
                                for val in found_query[query_name]:
                                    if p.match(val):
                                        logger.debug('query: %s matched regex', query_name)
                                        number_query_matching = number_query_matching + 1
                                        query_match_scrore = query_match_scrore + 2
                            except:
                                pass
                    else:
                        logger.debug(
                            'query %s in policy not found in request', query_name)
                if number_query_matching >= query_required_to_match:
                    query_match = True
                    policy_match_score = policy_match_score + query_match_scrore
        else:
            # No match critera for query, so match all..
            query_match = True
        #logger.debug(
        #    'policy %s result: day_match: %s time_match: %s env_match: %s header_match: %s method_match: %s path_regex_match: %s score %d',
        #    policy_hash, day_match, time_match, env_match, header_match, method_match, path_regex_match, policy_match_score
        #)
        if day_match and time_match and env_match and header_match and \
                              method_match and path_regex_match and query_match:
            logger.debug('policy with hash: %s has a match score of %d',
                         policy_hash, policy_match_score)
            if policy_match_score > most_specific_policy_match_score:
                most_specific_policy_match_score = policy_match_score
                most_specific_policy_hash = policy_hash
    logger.debug('policy rule most specific match was: %s with score: %d',
                 most_specific_policy_hash, most_specific_policy_match_score)
    return most_specific_policy_hash
