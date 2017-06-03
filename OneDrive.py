#!/usr/bin/env python

from __future__ import with_statement
from calendar import timegm

import __builtin__
import os
from os.path import basename, dirname
import stat
import errno
import logging
import yaml
import onedrivesdk

from fuse import FUSE, FuseOSError, Operations, LoggingMixIn

FileNotFound = getattr(__builtin__, "IOError", "FileNotFoundError")

class OneDriveFS(LoggingMixIn, Operations):
    def __init__(self, api, root, log=None, block_size=512):
        self.api, self.root, self.block_size = api, root, block_size
        self.log = log or logging.getLogger('{}.{}'.format(__name__, self.__class__.__name__))

    # Helpers
    # =======

    def _isdir(self, path):
        self.log.debug('Checking if is dir for %s', path)
        return self.api.item(path=path).get().folder is not None

    def _listdir(self, path):
        self.log.debug('Getting directory list for %s', path)
        return self.api.item(path=path).children.get()

    def _getitem(self, path):
        self.log.debug('Getting item for %s', path)
        return self.api.item(path=path).get()


    # Filesystem methods
    # ==================

    chmod = None
    chown = None
    readlink = None
    mknod = None
    symlink = None
    access = None

    # def access(self, path, amode):
    #     self.log.debug('Checking access for %s', path)
    #     try:
    #         return self._getitem(path)
    #         self.log.debug('Access to %s is granted', path)
    #     except onedrivesdk.error.OneDriveError:
    #         self.log.debug('Access to %s has error', path)
    #         return FuseOSError(errno.EACCES)

    def getattr(self, path, fh=None):
        obj = self._getitem(path)
        obj_mtime = obj.last_modified_date_time or obj.created_date_time
        st_mtime = timegm(obj_mtime.utctimetuple())
        return dict(
            st_mode=((stat.S_IFREG | 0644) if obj.file else (stat.S_IFDIR | 0755)),
            st_mtime=st_mtime,
            st_size=obj.size)

    def readdir(self, path, fh):
        return ['.', '..'] + [x.name for x in self._listdir(path).get()]
        # map(lambda x: x.name, self.api.item(path=path).children.get())

    def rmdir(self, path):
        if not self._isdir(path):
            raise FuseOSError(errno.ENOTDIR)
        elif self._listdir(path):
            raise FuseOSError(errno.ENOTEMPTY)
        self.api.item(path=path).delete()

    def mkdir(self, path, mode):
        name, parent = basename(path), dirname(path)
        item = onedrivesdk.Item()
        item.name = name
        item.folder = onedrivesdk.Folder()
        self.api.item(path=parent).children.add(item)


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
        self.api.item(path=path).delete()

    def rename(self, old, new):
        if old == new:
            return
        old_id = self.api.item(path=old).get().id
        renamed_item = onedrivesdk.Item()
        renamed_item.name = basename(new)
        renamed_item.id = old_id
        self.api.item(id=renamed_item.id).update(renamed_item)

    # def link(self, target, name):
        # return os.link(self._full_path(target), self._full_path(name))

    # def utimens(self, path, times=None):
        # return os.utime(self._full_path(path), times)

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

def main():
    optz = args()

    with open(optz.config, 'r') as configfile:
        cfg = yaml.load(configfile)

    log = logging.getLogger()
    logging.basicConfig(level=logging.WARNING
                        if not optz.debug else logging.DEBUG)

    opts_fuse = dict(foreground=optz.foreground or optz.debug)
    log.debug('FUSE: {%s}', opts_fuse)
    log.debug('Onedrive client id: %s, redirect uri: %s', cfg['client_id'], cfg['redirect_uri'])

    api = login_onedrive(cfg['client_id'], cfg['client_secret'], cfg['redirect_uri'])

    FUSE(OneDriveFS(api, root='/', log=log, block_size=cfg['block_size']), optz.mountpoint, foreground=True)

if __name__ == '__main__':
    main()
