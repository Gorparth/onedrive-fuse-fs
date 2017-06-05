"""Onedrive util config module"""

import configparser
import logging
import os

LOGGER = logging.getLogger(__name__)


def get_conf(path, default_conf=None):
    """Parse onedrive fuse driver configuration"""
    conf = configparser.ConfigParser()

    if default_conf:
        conf.read_dict(default_conf)

    try:
        with open(path) as conf_file:
            conf.read_file(conf_file)
    except IOError:
        pass

    LOGGER.debug('configuration resulting from merging default and %s: %s',
                 path, {section: dict(conf[section]) for section in conf})

    return conf
