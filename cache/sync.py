"""Sync OneDrive API items with SQLite database"""

import logging
from .cursors import mod_cursor

class SyncMixin(object):
    def __init__(self, log=None):
        self.items = []
        self.log = log or logging.getLogger(
            '{}.{}'.format(__name__, self.__class__.__name__))
        log.debug('Sync mixin finish init')

    def insert_items(self, items):
        for item in items:
            path = item.parent_reference.path if item.parent_reference else None
            if path == None:
                path = '/'
            path = path.replace('/drive/root:','')
            if path == '':
                path = '/'
            common = dict(created_date_time=item.created_date_time,
                          id=item.id, name=item.name,
                          last_modified_date_time=item.last_modified_date_time,
                          path=path, deleted=item.deleted is not None)
            if item.file:
                new_file = dict(size=item.size, isFolder=False, **common)
                self.items.append(new_file)
            else:
                new_folder = dict(isFolder=True, **common)
                self.items.append(new_folder)

    def commit_items(self):
        if len(self.items) == 0:
            return

        self._commit_items()
        self._remove_deleted()

    def _commit_items(self):
        with mod_cursor(self._conn) as conn:
            for f in self.items:
                conn.execute('INSERT OR REPLACE INTO items (id, isFolder, name, created, modified, size, path) '
                             'VALUES (?, ?, ?, ?, ?, ?, ?)', [ f['id'], 1 if f['isFolder'] else 0,
                              f['name'], f['created_date_time'],
                                f['last_modified_date_time'], f['size'] if f.has_key('size') else None, f['path']])

    def _remove_deleted(self):
        with mod_cursor(self._conn) as conn:
            deleted = [x for x in self.items if x['deleted']]

            for d in deleted:
                conn.execute('DELETE FROM items WHERE id=?', [d['id']])
