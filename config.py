from distutils.command.config import config
import json
import logging
import os
import yaml
import urllib.request as urllibrequest
import utils

from timer import Timer
from deepdiff import DeepDiff

from const import DEFAULT_CONFIG_FILE, DEFAULT_LOG_LEVEL, DEFAULT_POLICIES

CONFIG_FILE: str = None
LOG_LEVEL: str = None
RELOAD_INTERVAL: int = 0
RELOAD_TIMER: Timer = None
BYPASS_RELOAD: False
POLICIES: dict = {}

import logging_config

logger: logging.Logger = logging_config.init_logging()


def set_settings(config_file, log_level, reload_timer):
    global CONFIG_FILE, LOG_LEVEL, RELOAD_INTERVAL
    LOG_LEVEL = log_level
    logger.setLevel(LOG_LEVEL)
    RELOAD_INTERVAL = reload_timer
    if RELOAD_INTERVAL > 0:
        logger.info('setting reloar timer to API value %d', RELOAD_INTERVAL)
    if not config_file == CONFIG_FILE:
        CONFIG_FILE = utils.sub_env_variables(config_file)
        logger.info('setting config file to API value: %s', CONFIG_FILE)
    reload_configuration()


def load_settings_from_config_dict(config_dict):
    global LOG_LEVEL
    if 'debug' in config_dict and config_dict['debug']:
        if not LOG_LEVEL:
            LOG_LEVEL = 'DEBUG'
            logger.info('setting configuration logging level to: %s', LOG_LEVEL)
            logger.setLevel(logging.DEBUG)
    else:
        log_level: str = os.getenv('LOG_LEVEL', DEFAULT_LOG_LEVEL)
        if not LOG_LEVEL:
            logger.info('setting default logging level to: %s', log_level)
            logger.setLevel(log_level)
            LOG_LEVEL = log_level
    if 'reload_timer' in config_dict and config_dict['reload_timer']:
        if not RELOAD_TIMER and not RELOAD_INTERVAL:
            if config_dict['reload_timer'] > 0:
                logger.info(
                'setting configuration reload timer to %d seconds',
                config_dict['reload_timer'])
            reload_on_time(config_dict['reload_timer'])
        else:
            reload_on_time(RELOAD_INTERVAL)


def read_config_from_local_file(filepath: str):
    logger.debug('reading configuration from file://%s', filepath)
    if os.path.exists(filepath):
        with open(filepath) as cf:
            config_dict = dict()
            try:
                config_dict = yaml.safe_load(cf)
            except:
                try:
                    config_dict = json.loads(cf)
                except:
                    pass
            if config_dict:
                load_settings_from_config_dict(config_dict)
                return config_dict['policies']
            else:
                logger.error("Can not load config: %s as YAML or JSON",
                             filepath)
    return {}


def read_config_from_url(fileurl: str):
    logger.debug('reading configuration from %s', fileurl)
    try:
        with urllibrequest.urlopen(fileurl) as cf:
            config_dict = dict()
            try:
                config_dict = yaml.safe_load(cf)
            except:
                try:
                    config_dict = json.loads(cf)
                except:
                    pass
            if config_dict:
                load_settings_from_config_dict(config_dict)
                return config_dict['policies']
            else:
                logger.error("Can not load config: %s as YAML or JSON",
                             fileurl)
            return config_dict['policies']
    except Exception as error:
        logger.error('Error retrieving config file from url: %s: %s',
                     fileurl, error)
    return {}


def export_config_file_as_yaml():
    return yaml.safe_dump(CONFIG_FILE)


def initialize_configurations(config_file=None):
    global CONFIG_FILE, BYPASS_RELOAD
    if not config_file:
        config_file = os.getenv('CONFIG_FILE', DEFAULT_CONFIG_FILE)
    BYPASS_RELOAD = os.getenv('BYPASS_RELOAD', 'False').lower() in ('true', '1', 't')
    if BYPASS_RELOAD:
        logger.warning('BYPASS_RELOAD is set.. configuration reloading disabled')
    CONFIG_FILE = utils.sub_env_variables(config_file)
    policy_list = []
    if utils.is_url(config_file):
        policy_list = read_config_from_url(CONFIG_FILE)
    elif os.path.exists(config_file):
        policy_list = read_config_from_local_file(CONFIG_FILE)
    return initialize_policies(policy_list)


def initialize_policies(policy_list):
    global POLICIES
    for policy in policy_list:
        policy['repeated'] = {}
        POLICIES[utils.get_policy_hash(policy)] = policy
    return POLICIES


def reload_configuration():
    global POLICIES
    policy_list = []
    if utils.is_url(CONFIG_FILE):
        policy_list = read_config_from_url(CONFIG_FILE)
    elif os.path.exists(CONFIG_FILE):
        policy_list = read_config_from_local_file(CONFIG_FILE)
    for policy in policy_list:
        policy_hash = utils.get_policy_hash(policy)
        if 'repeated' not in POLICIES[policy_hash]:
            POLICIES[policy_hash]['repeated'] = 0
        if policy_hash in POLICIES:
            policy['repeated'] = POLICIES[policy_hash]['repeated']
        policy_diff = DeepDiff(POLICIES[policy_hash], policy, ignore_string_case=True)
        if policy_diff:
            logger.info(
                'loading policy %s from configuration reload', policy_hash)
            POLICIES[policy_hash] = policy


def reload_on_time(reload_interval):
    global RELOAD_INTERVAL, RELOAD_TIMER
    if RELOAD_TIMER:
        RELOAD_TIMER.cancel()
    if reload_interval > 0 and not BYPASS_RELOAD:
        RELOAD_INTERVAL = reload_interval
        RELOAD_TIMER = Timer(
            RELOAD_INTERVAL, True,
            reload_configuration)
    else:
        logger.info('disabling configuration reloading')


def get_next_policy_id():
    high_id = 0
    for p in POLICIES:
        if POLICIES[p]['id'] >= high_id:
            high_id = int(POLICIES[p]['id'])
    return high_id + 1
