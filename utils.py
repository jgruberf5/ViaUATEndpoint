import logging
import ipaddress
import json
import os
import re
import validators

import logging_config

logger = logging_config.init_logging()


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


def get_policy_hash(policy: dict):
    return "%d-%s-%s" % (policy['id'], policy['src_cidr'], policy['method'])


def get_client_ip_match(client_ips, policies):
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


def get_matched_policy_hash(request, policy_hashes, policies):
    most_specific_policy_hash = None
    most_specific_policy_match_score = 0
    for policy_hash in policy_hashes:
        policy_match_score = 0
        policy = policies[policy_hash]
        # env matching is present and value
        env_match = False
        if 'env' in policy and policy['env']:
            required_to_match = 0
            if 'env_policy_match' not in policy:
                policy['env_policy_match'] = 'and'
            if policy['env_policy_match'].lower() == 'and':
                required_to_match = len(policy['env'])
            elif policy['env_policy_match'].lower() == 'or':
                required_to_match = 1
            else:
                try:
                    required_to_match = int(policy['env_match_policy'])
                except:
                    pass
            if required_to_match:
                env_match_scrore = 0
                number_envs_matching = 0
                # we have to interate through them all
                # in case the match with the higher
                # precise matching is latter in the match
                for env in policy['env']:
                    env_name = list(env.keys())[0]
                    env_match_value = env[env_name]
                    if os.getenv(env_name, None):
                        logger.debug('checking env %s match for %s',
                                     env, env_match_value)
                        if env_match_value.lower() == 'any':
                            logger.debug('env: %s matched any', env)
                            number_envs_matching = number_envs_matching + 1
                            env_match_scrore = env_match_scrore + 1
                        elif env_match_value == os.getenv(env_name):
                            logger.debug('env: %s matched exact', env)
                            number_envs_matching = number_envs_matching + 1
                            env_match_scrore = env_match_scrore + 3
                        else:
                            try:
                                p = re.compile(env_match_value)
                                if p.match(os.getenv(env_name)):
                                    logger.debug('env: %s matched regex', env)
                                    number_envs_matching = number_envs_matching + 1
                                    env_match_scrore = env_match_scrore + 2
                            except:
                                pass
                    else:
                        logging.debug('env %s in policy not found in environment', env_name)
                if number_envs_matching >= required_to_match:
                    env_match = True
                    policy_match_score = policy_match_score + env_match_scrore
        else:
            # No match critera for env, so match all..
            env_match = True
        # Header matching is presence and value
        header_match = False
        if 'headers' in policy and policy['headers']:
            # If multiple headers are present, all must match.
            required_to_match = 0
            if 'header_match_policy' not in policy:
                policy['header_match_policy'] = 'and'
            if policy['header_match_policy'].lower() == 'and':
                required_to_match = len(policy['headers'])
            elif policy['header_match_policy'].lower() == 'or':
                required_to_match = 1
            else:
                try:
                    required_to_match = int(policy['header_match_policy'])
                except:
                    pass
            if required_to_match:
                header_match_scrore = 0
                number_headers_matching = 0
                # avoid looping over and over
                found_headers = request.headers.keys()
                # logger.debug('request headers: %s', found_headers)
                # we have to interate through them all
                # in case the match with the higher
                # precise matching is latter in the match
                for header in policy['headers']:
                    header_name = list(header.keys())[0].lower()
                    header_match_value = header[header_name]
                    if header_name in found_headers:
                        logger.debug(
                            'checking header %s:%s match for %s',
                            header_name,
                            request.headers.get(header_name),
                            header_match_value)
                        if header_match_value.lower() == 'any':
                            logger.debug('header: %s matched any', header_name)
                            number_headers_matching = number_headers_matching + 1
                            header_match_scrore = header_match_scrore + 1
                        elif header_match_value == request.headers.get(
                                header_name):
                            logger.debug('header: %s matched exact',
                                         header_name)
                            number_headers_matching = number_headers_matching + 1
                            header_match_scrore = header_match_scrore + 3
                        else:
                            try:
                                p = re.compile(header_match_value)
                                if p.match(request.headers.get(header_name)):
                                    logger.debug('header: %s matched regex',
                                                 header_name)
                                    number_headers_matching = number_headers_matching + 1
                                    header_match_scrore = header_match_scrore + 2
                            except:
                                pass
                    else:
                        logger.debug(
                            'header %s in policy not found in request', header_name)
                if number_headers_matching >= required_to_match:
                    header_match = True
                    policy_match_score = policy_match_score + header_match_scrore
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
        if env_match and header_match and method_match and path_regex_match:
            logger.debug('policy with hash: %s has a match score of %d',
                         policy_hash, policy_match_score)
            if policy_match_score > most_specific_policy_match_score:
                most_specific_policy_match_score = policy_match_score
                most_specific_policy_hash = policy_hash
    logger.debug('policy rule most specific match was: %s with score: %d',
                 most_specific_policy_hash, most_specific_policy_match_score)
    return most_specific_policy_hash
