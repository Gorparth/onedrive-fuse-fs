#!/usr/bin/env python

from __future__ import with_statement
from calendar import timegm
from time import time, sleep

import __builtin__
from os.path import basename, dirname, join
import stat
import errno
import logging
import onedrivesdk
from multiprocessing import Process
import sys

from utils.conf import get_conf
from cache import db

from fuse import FUSE, FuseOSError, Operations, LoggingMixIn

FileNotFound = getattr(__builtin__, "IOError", "FileNotFoundError")


class OneDriveFS(LoggingMixIn, Operations):
    def __init__(self, api, root, cache, log=None, block_size=512):
        self.api, self.root, self.block_size, self.handles, self.cache = api, root, block_size, {}, cache

        self.log = log or logging.getLogger(
            '{}.{}'.format(__name__, self.__class__.__name__))

    # Helpers
    # =======

    def _get_item_path_name(self, path):
        folder = dirname(path)
        name = basename(path)

        if name == '':
            name = 'root'
        return [folder, name]

    def _isdir(self, path):
        self.log.debug('Checking if is dir for %s', path)
        item_path = self._get_item_path_name(path)
        return self.cache.isFolder(item_path[0], item_path[1])

    def _listdir(self, path):
        self.log.debug('Getting directory list for %s', path)
        return self.cache.get_children(path)

    def _getitem(self, path):
        self.log.debug('Getting item for %s', path)
        item_path = self._get_item_path_name(path)
        return self.cache.get_item(item_path[0], item_path[1])

    # Filesystem methods
    # ==================

    def chmod(self, path, mode):
        """Not implemented."""
        pass


    def chown(self, path, uid, gid):
        """Not implemented."""
        pass

    def getattr(self, path, fh=None):
        if fh:
            node = self.handles[fh]
        else:
            node = self._getitem(path)
            if not node:
                raise FuseOSError(errno.ENOENT)

        obj_mtime = node.modified or node.created
        times = dict(st_atime=time(),
                     st_mtime=timegm(obj_mtime.utctimetuple()),
                     st_ctime=timegm(node.created.utctimetuple()))

        if node.isFolder:
            return dict(st_mode=stat.S_IFDIR | 0o0777,
                        st_nlink=1,
                        **times)
        else:
            return dict(st_mode=stat.S_IFREG | 0o0666,
                        st_nlink=1,
                        st_size=node.size,
                        st_blocksize=self.block_size,
                        st_blocks=node.size//self.block_size,
                        **times)

    def readdir(self, path, fh):
        self.log.debug('Reading dir %s', path)
        node = self._getitem(path)

        if not node:
            raise FuseOSError(errno.ENOENT)
        if not node.isFolder:
            raise FuseOSError(errno.ENOTDIR)

        return ['.', '..'] + [x.name for x in self._listdir(path)]

    def rmdir(self, path):
        if not self._isdir(path):
            raise FuseOSError(errno.ENOTDIR)
        elif self._listdir(path):
            raise FuseOSError(errno.ENOTEMPTY)
        item = self._getitem(path)
        self.api.item(path=path).delete()
        self.cache.delete_item(item.id)


    def mkdir(self, path, mode):
        name, parent = basename(path), dirname(path)
        item = onedrivesdk.Item()
        item.name = name
        item.folder = onedrivesdk.Folder()
        new_item = self.api.item(path=parent).children.add(item)
        self.cache.add_item(new_item.id, name, parent, new_item.created_date_time)


    def statfs(self, path):
        quota = self.api.drive.get().quota
        return dict(f_bsize=self.block_size,
                    f_frsize=self.block_size,
                    f_blocks=quota.total // self.block_size,
                    f_bfree=quota.remaining // self.block_size,
                    f_bavail=quota.remaining // self.block_size,
                    f_namemax=256
                   )

    def unlink(self, path):
        if self._isdir(path):
            raise FuseOSError(errno.EISDIR)
        item = self._getitem(path)
        self.cache.delete_item(item.id)
        self.api.item(path=path).delete()

    def rename(self, old, new):
        if old == new:
            return
        old_id = self.api.item(path=old).get().id
        renamed_item = onedrivesdk.Item()
        renamed_item.name = basename(new)
        renamed_item.id = old_id
        self.cache.update_name(old_id, renamed_item.name)
        self.api.item(id=renamed_item.id).update(renamed_item)

    # File methods
    # ============

    # def open(self, path, flags):
    #     full_path = self._full_path(path)
    #     return os.open(full_path, flags)

    # def create(self, path, mode, fi=None):
    #     full_path = self._full_path(path)
    #     return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)

    # def read(self, path, length, offset, fh):
    #     os.lseek(fh, offset, os.SEEK_SET)
    #     return os.read(fh, length)

    # def write(self, path, buf, offset, fh):
    #     os.lseek(fh, offset, os.SEEK_SET)
    #     return os.write(fh, buf)

    # def truncate(self, path, length, fh=None):
    #     full_path = self._full_path(path)
    #     with open(full_path, 'r+') as f:
    #         f.truncate(length)

    # def flush(self, path, fh):
    #     return os.fsync(fh)

    # def release(self, path, fh):
    #     return os.close(fh)

    # def fsync(self, path, fdatasync, fh):
    #     return self.flush(path, fh)

def login_onedrive(client_id, client_secret, redirect_uri):
    scopes = ['wl.signin', 'wl.offline_access', 'onedrive.readwrite']
    client = onedrivesdk.get_consumer_client(client_id, scopes)

    try:
        client.auth_provider.load_session()
        client.auth_provider.refresh_token()
    except FileNotFound:
        authorization_code = authorize_onedrive(client, redirect_uri)
        client.auth_provider.authenticate(authorization_code, redirect_uri, client_secret)
        client.auth_provider.save_session()

    return client

def authorize_onedrive(client, redirect_uri):
    auth_url = client.auth_provider.get_auth_url(redirect_uri)

    # Ask for the code
    print 'Paste this URL into your browser, approve the app\'s access.'
    print 'Copy everything in the address bar after "code=", and paste it below.'
    print auth_url
    code = raw_input('Paste code here: ')
    return code

def sync_onedrive_items(cache, api, log, sync_time=None):
    while True:
        token = cache.config.get('onedrive_delta_token')
        log.debug('Onedrive delta token is %s', token)
        items = api.item(path='/').delta(token).get()
        log.debug('new items to sync %i', len(items))
        while len(items) > 0:
            cache.insert_items(items)
            token = items.token
            items = api.item(path='/').delta(token).get()
        cache.commit_items()
        cache.config.update(dict(onedrive_delta_token=token))
        log.debug('Onedrive items synced')
        if sync_time:
            sleep(sync_time)
        else:
            return


def args():
    import argparse
    parser = argparse.ArgumentParser(description='Mount OneDrive as a FUSE filesystem.')
    parser.add_argument('config',
                        metavar='config_path',
                        nargs='?', default='onedrive.conf',
                        help='Writable configuration state-file (yaml).'
                        ' Used to store authorization_code, access and refresh tokens.'
                        ' Should initially contain "{client: {id: xxx, secret: yyy}}".'
                        ' Default: %(default)s')
    parser.add_argument('mountpoint', metavar='path', help='Path to mount OneDrive to.')
    parser.add_argument('-f', '--foreground', action='store_true',
                        help='Dont fork into background after mount succeeds.')
    parser.add_argument('--debug', action='store_true',
                        help='Verbose operation mode. Implies --foreground.')
    optz = parser.parse_args()

    return optz

def set_encoding(force_utf=False, logger=None):
    """Sets the default encoding to UTF-8 if none is set.
    :param force_utf: force UTF-8 output"""

    enc = str.lower(sys.stdout.encoding)
    print enc
    utf_flag = False

    if not enc or force_utf:
        import io

        sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding='utf-8')
        sys.stderr = io.TextIOWrapper(sys.stderr.detach(), encoding='utf-8')
        utf_flag = True
    else:
        def unicode_hook(type_, value, traceback):
            sys.__excepthook__(type_, value, traceback)
            if type_ == UnicodeEncodeError:
                logger.error('Please set your locale or use the "--utf" flag.')

        sys.excepthook = unicode_hook

    return utf_flag

def main():
    optz = args()

    cfg = get_conf(optz.config)

    log = logging.getLogger()
    logging.basicConfig(level=logging.WARNING
                        if not optz.debug else logging.DEBUG)

    opts_fuse = dict(foreground=optz.foreground or optz.debug)
    log.debug('FUSE: {%s}', opts_fuse)
    log.debug('Onedrive client id: %s, redirect uri: %s', cfg['onedrive']['client_id'], cfg['onedrive']['redirect_uri'])

    api = login_onedrive(
        cfg['onedrive']['client_id'],
        cfg['onedrive']['client_secret'],
        cfg['onedrive']['redirect_uri'])

    path = join(dirname(__file__))
    items_cache = db.ItemsCache(cache_path=path, settings_path=optz.config, log=log)

    log.debug('First sync')
    sync_onedrive_items(items_cache, api, log)
    log.debug('End first sync')

    sync_process = Process(target=sync_onedrive_items, args=(items_cache, api, log, int(cfg['onedrive']['sync_time'])))
    sync_process.start()

    FUSE(OneDriveFS(api, root='/', log=log, cache=items_cache,
        block_size=int(cfg['fuse']['block_size'])), optz.mountpoint, foreground=True)

if __name__ == '__main__':
    main()
