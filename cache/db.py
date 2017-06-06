"""Onedrive cache db module"""

import configparser
import logging
import os
import re
import sqlite3
from threading import local
import sys

from utils.conf import get_conf

from .cursors import cursor
# from .format import FormatterMixin
from .queries import QueryMixin
from .schema import SchemaMixin
from .sync import SyncMixin

_ROOT_ID_SQL = "SELECT id FROM items WHERE name IS '/' AND isFolder == 1 ORDER BY created"

_DEF_CONF_ = configparser.ConfigParser()
_DEF_CONF_['sqlite'] = dict(filename='cache.db', busy_timeout=30000, journal_mode='wal')

class IntegrityError(Exception):
    """Integrity error in sql exception"""
    def __init__(self, msg):
        super(IntegrityError, self).__init__(msg)
        self.msg = msg

    def __str__(self):
        return repr(self.msg)


def _create_conn(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row # allow dict-like access on rows with col name
    return conn


def _regex_match(pattern, cell):
    if cell is None:
        return False
    return re.match(pattern, cell, re.IGNORECASE) is not None

class ItemsCache(SchemaMixin, SyncMixin, QueryMixin):
    """Onedrive items cache db"""
    IntegrityCheckType = dict(full=0, quick=1, none=2)
    """types of SQLite integrity checks"""

    def __init__(self, cache_path='', settings_path='', check=IntegrityCheckType['full'], log=None):
        super(ItemsCache, self).__init__(log=log)
        self._conf = get_conf(settings_path, _DEF_CONF_)
        self.log = log or logging.getLogger(
            '{}.{}'.format(__name__, self.__class__.__name__))

        self.db_path = os.path.join(cache_path, self._conf['sqlite']['filename'])
        self.log.debug('The db path is %s', self.db_path)
        self.thread_local = local()

        self.integrity_check(check)
        self.init()

        self._conn.create_function('REGEXP', _regex_match.__code__.co_argcount, _regex_match)

        with cursor(self._conn) as conn:
            conn.execute(_ROOT_ID_SQL)
            row = conn.fetchone()
            if not row:
                self.root_id = '/'
                return
            first_id = row['id']

            if conn.fetchone():
                raise IntegrityError('Could not uniquely identify root node.')

            self.root_id = first_id

        self._execute_pragma('busy_timeout', self._conf['sqlite']['busy_timeout'])
        self._execute_pragma('journal_mode', self._conf['sqlite']['journal_mode'])

    def _execute_pragma(self, key, value):
        with cursor(self._conn) as conn:
            conn.execute('PRAGMA %s=%s;' % (key, value))
            result = conn.fetchone()
        if result:
            self.log.debug('Set %s to %s. Result: %s.', key, value, result[0])
            return result[0]

    @property
    def _conn(self):
        if not hasattr(self.thread_local, '_conn'):
            # pylint: disable=W0212
            self.thread_local._conn = _create_conn(self.db_path)
            # pylint: disable=W0212
        return self.thread_local._conn

    def integrity_check(self, type_):
        """Performs a `self-integrity check
        <https://www.sqlite.org/pragma.html#pragma_integrity_check>`_ on the database."""

        with cursor(self._conn) as conn:
            if type_ == ItemsCache.IntegrityCheckType['full']:
                result = conn.execute('PRAGMA integrity_check;')
            elif type_ == ItemsCache.IntegrityCheckType['quick']:
                result = conn.execute('PRAGMA quick_check;')
            else:
                return
            result = conn.fetchone()
            if not result or result[0] != 'ok':
                self.log.warn('Sqlite database integrity check failed. '
                            'You may need to clear the cache if you encounter any errors.')
