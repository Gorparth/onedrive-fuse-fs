"""This module handle the schema creation for onedrive cache"""

import logging
from sqlite3 import OperationalError
from .cursors import cursor, mod_cursor

_CREATION_SCRIPT = """
    CREATE TABLE items (
        id VARCHAR(50) NOT NULL,
        isFolder INTEGER NOT NULL,
        name VARCHAR(256) NOT NULL,
        size BIGINT,
        created DATETIME,
        modified DATETIME,
        path VARCHAR(2048),
        PRIMARY KEY (id)
    );

    CREATE TABLE config (
        key VARCHAR(50) NOT NULL,
        value VARCHAR(255) NOT NULL,
        PRIMARY KEY (key)
    );

    CREATE INDEX ix_items_name ON items(name);
    CREATE INDEX ix_items_path ON items(path);
    PRAGMA user_version = 0;
    """

class SchemaMixin(object):
    """This class handles schema creation"""
    _DB_SCHEMA_VER = 0

    def init(self):
        """This method init schema creation"""
        logger = logging.getLogger(__name__)
        try:
            self.create_tables()
        except OperationalError:
            pass
        with cursor(self._conn) as conn:
            conn.execute('PRAGMA user_version')
            result = conn.fetchone()
        version = result[0]

        logger.info('DB schema version is %i', version)

        if self._DB_SCHEMA_VER > version:
            raise NotImplementedError

        self.config = _ConfigStorage(self._conn)


    def create_tables(self):
        """This methods handle table creation"""
        self._conn.executescript(_CREATION_SCRIPT)
        self._conn.commit()

class _ConfigStorage(object):
    def __init__(self, conn):
        self.conn = conn

    def __getitem__(self, key):
        with cursor(self.conn) as conn:
            conn.execute('SELECT value FROM config WHERE key = (?)', [key])
            result = conn.fetchone()
        if result:
            return result['value']
        else:
            raise KeyError

    def __setitem__(self, key, value):
        with mod_cursor(self.conn) as conn:
            conn.execute('INSERT OR REPLACE INTO config VALUES (?, ?)', [key, value])

    def get(self, key, default=None):
        """This methods get a key from the config or default if not exists"""
        try:
            return self.__getitem__(key)
        except KeyError:
            return default

    def update(self, dict_):
        """This method creates/updates a config key"""
        for key in dict_.keys():
            self.__setitem__(key, dict_[key])
