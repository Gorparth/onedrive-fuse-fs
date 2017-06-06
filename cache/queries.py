import logging
from .cursors import cursor, mod_cursor
from datetime import datetime

GET_ITEM_BY_NAME = """SELECT * FROM items WHERE path LIKE ? AND name LIKE ?"""

GET_CHILDREN_BY_PATH = """SELECT * FROM items WHERE path LIKE ?"""

DELETE_ITEM_BY_ID = """DELETE FROM items WHERE id=?"""

ADD_ITEM = """INSERT INTO items (id, isFolder, name, created, modified, path) VALUES (?, 1, ?, ?, ?, ?)"""

RENAME_ITEM = """UPDATE items SET name=? WHERE id=?"""

def datetime_from_string(dt):
    try:
        dt = datetime.strptime(dt, '%Y-%m-%d %H:%M:%S.%f')
    except ValueError:
        dt = datetime.strptime(dt, '%Y-%m-%d %H:%M:%S')
    return dt

class Item(object):
    def __init__(self, row):
        self.id = row['id']
        self.isFolder = row['isFolder']
        self.name = row['name']
        self.size = row['size']
        self.created = datetime_from_string(row['created'])
        self.modified = datetime_from_string(row['modified'])
        self.path = row['path']

class QueryMixin(object):
    def __init__(self, log=None):
        self.log = log or logging.getLogger('{}.{}'.format(__name__, self.__class__.__name__))

    def isFolder(self, path, name):
        item = self.get_item(path, name)
        return item.isFolder == 1 if item else None

    def get_children(self, path):
        children = []
        with cursor(self._conn) as c:
            c.execute(GET_CHILDREN_BY_PATH, [path.encode('utf-8')])
            item = c.fetchone()
            while item:
                children.append(Item(item))
                item = c.fetchone()
        return children

    def get_item(self, path, name):
        self.log.debug('Getting item for path \'%s\' and name \'%s\'', path, name)
        with cursor(self._conn) as c:
            c.execute(GET_ITEM_BY_NAME, [path, name])
            r = c.fetchone()
        return Item(r) if r else None

    def delete_item(self, id):
        self.log.debug('Deleting item with id %s', id)
        with mod_cursor(self._conn) as c:
            c.execute(DELETE_ITEM_BY_ID, [id])

    def add_item(self, id, name, path, date):
        self.log.debug('Adding item %s', name)
        with mod_cursor(self._conn) as c:
            c.execute(ADD_ITEM, [id, name, date, date, path])

    def update_name(self, id, name):
        self.log.debug('Renaming item %s', id)
        with mod_cursor(self._conn) as c:
            c.execute(RENAME_ITEM, [name, id])

