import logging
import os
import yaml
import urllib.request as urllibrequest
import utils

from const import DEFAULT_CONFIG_FILE, DEFAULT_LOG_LEVEL, DEFAULT_POLICIES

CONFIG_FILE: str = DEFAULT_CONFIG_FILE
RELOAD_TIMER: int = 0

import logging_config

logger = logging_config.init_logging()


def read_config_from_local_file(filepath: str):
    global RELOAD_TIMER
    logger.info('reading configuration from file://%s', filepath)
    if os.path.exists(filepath):
        with open(filepath) as cf:
            try:
                cf_obj = yaml.safe_load(cf)
                if 'debug' in cf_obj and cf_obj['debug']:
                    logger.setLevel(logging.DEBUG)
                if 'reload_timer' in cf_obj and cf_obj['reload_timer']:
                    RELOAD_TIMER = cf_obj['reload_timer']
                    logger.info('setting configuration reload timer to %d seconds', RELOAD_TIMER)
                return cf_obj['policies']
            except Exception as error:
                logger.error("Can not load config file: %s: %s",
                             filepath, error)
    return {}


def read_config_from_url(fileurl: str):
    global RELOAD_TIMER
    logger.info('reading configuration from %s', fileurl)
    try:
        with urllibrequest.urlopen(fileurl) as cf:
            cf_obj = yaml.safe_load(cf)
            if 'debug' in cf_obj and cf_obj['debug']:
                logger.setLevel(logging.DEBUG)
            if 'reload_timer' in cf_obj and cf_obj['reload_timer']:
                RELOAD_TIMER = cf_obj['reload_timer']
            return cf_obj['policies']
    except Exception as error:
        logger.error('Error retrieving config file from url: %s: %s',
                     fileurl, error)
    return {}


def intialize_config():
    global CONFIG_FILE
    CONFIG_FILE = os.getenv('CONFIG_FILE', DEFAULT_CONFIG_FILE)
    log_level: str = os.getenv('LOG_LEVEL', DEFAULT_LOG_LEVEL)
    if log_level in logging._nameToLevel:
        logger.info('setting logging level to: %s', log_level)
        logger.setLevel(log_level)
    else:
        raise ValueError('Configuration error: LOG_LEVEL must be in: %s',
                         logging._nameToLevel.keys())
    return load_policies()


def load_policies(config_file=None, reload_timer=0):
    global CONFIG_FILE, RELOAD_TIMER
    config_policies = []
    policies: dict = {}
    last_id: int = 0
    if config_file:
        if utils.is_url(config_file) or os.path.exists(config_file):
            CONFIG_FILE = utils.sub_env_variables(config_file)
    if reload_timer > 0:
        RELOAD_TIMER = reload_timer
    if utils.is_url(CONFIG_FILE):
        config_policies = read_config_from_url(CONFIG_FILE)
    else:
        config_policies = read_config_from_local_file(CONFIG_FILE)
    for policy in config_policies:
        if policy['id'] > last_id:
            last_id = policy['id']
        policy['repeated'] = {}
        policies[utils.get_policy_hash(policy)] = policy
    return (last_id, policies)
