#!/usr/bin/env python

from __future__ import with_statement
from calendar import timegm
from time import time, sleep

from os.path import basename, dirname, join
import stat
import errno
import logging
import onedrivesdk
from multiprocessing import Process
from threading import Lock
from collections import defaultdict, deque
import sys
import os
import http.client as http
import requests


from utils.conf import get_conf
from cache import db

from fuse import FUSE, FuseOSError, Operations, LoggingMixIn

logger = logging.getLogger(__name__)

def response_chunk(api, path, offset, length):
    ok_codes = [http.PARTIAL_CONTENT]
    end = offset + length - 1
    logger.debug('chunk o %d l %d' % (offset, length))

    url = api.base_url + 'drive/root%3A' + path + '%3A/content'
    headers={'Range': 'bytes=%d-%d' % (offset, end), 'Authorization': 'Bearer %s' % api.auth_provider.access_token}
    r = requests.get(url, stream=True, headers=headers)

    if r.status_code not in ok_codes:
        raise requests.RequestException(r.status, r.text)

    return r

class ReadProxy(object):
    """Dict of stream chunks for consecutive read access of files."""

    def __init__(self, api, open_chunk_limit, timeout, dl_chunk_size):
        self.api = api
        self.lock = Lock()
        self.files = defaultdict(lambda: ReadProxy.ReadFile(open_chunk_limit, timeout, dl_chunk_size))

    class StreamChunk(object):
        """StreamChunk represents a file node chunk as a streamed ranged HTTP response
        which may or may not be partially read."""

        __slots__ = ('offset', 'r', 'end')

        def __init__(self, api, path, offset, length, **kwargs):
            self.offset = offset
            """the first byte position (fpos) available in the chunk"""

            self.r = response_chunk(api, path, offset, length)
            """:type: requests.Response"""

            self.end = offset + int(self.r.headers['content-length']) - 1
            """the last byte position (fpos) contained in the chunk"""

        def has_byte_range(self, offset, length):
            """Tests whether chunk begins at **offset** and has at least **length** bytes remaining."""
            logger.debug('s: %d-%d; r: %d-%d'
                         % (self.offset, self.end, offset, offset + length - 1))
            if offset == self.offset and offset + length - 1 <= self.end:
                return True
            return False

        def get(self, length):
            """Gets *length* bytes beginning at current offset.
            :param length: the number of bytes to get
            :raises: Exception if less than *length* bytes were received \
             but end of chunk was not reached"""

            b = next(self.r.iter_content(length))
            self.offset += len(b)

            if len(b) < length and self.offset <= self.end:
                logger.warning('Chunk ended unexpectedly.')
                raise Exception
            return b

        def close(self):
            """Closes connection on the stream."""
            self.r.close()

    class ReadFile(object):
        """Represents a file opened for reading.
        Encapsulates at most :attr:`MAX_CHUNKS_PER_FILE` open chunks."""

        __slots__ = ('chunks', 'access', 'lock', 'timeout', 'dl_chunk_size')

        def __init__(self, open_chunk_limit, timeout, dl_chunk_size):
            self.dl_chunk_size = dl_chunk_size
            self.chunks = deque(maxlen=open_chunk_limit)
            self.access = time()
            self.lock = Lock()
            self.timeout = timeout

        def get(self, api, path, offset, length, total):
            """Gets a byte range from existing StreamChunks"""

            with self.lock:
                i = len(self.chunks) - 1
                while i >= 0:
                    c = self.chunks[i]
                    if c.has_byte_range(offset, length):
                        try:
                            bytes_ = c.get(length)
                        except:
                            self.chunks.remove(c)
                        else:
                            return bytes_
                    i -= 1

            try:
                with self.lock:
                    chunk = ReadProxy.StreamChunk(api, path, offset, self.dl_chunk_size, timeout=self.timeout)
                    if len(self.chunks) == self.chunks.maxlen:
                        self.chunks[0].close()

                    self.chunks.append(chunk)
                    return chunk.get(length)
            except Exception as e:
                logger.error(e)

        def clear(self):
            """Closes chunks and clears chunk deque."""
            with self.lock:
                for chunk in self.chunks:
                    try:
                        chunk.close()
                    except:
                        pass
                self.chunks.clear()

    def get(self, path, offset, length, total):
        with self.lock:
            f = self.files[path]
        return f.get(self.api, path, offset, length, total)

    def invalidate(self):
        pass

    def release(self, path):
        with self.lock:
            f = self.files.get(path)
        if f:
            f.clear()

class WriteProxy(object):
    """Collection of WriteStreams for consecutive file write operations."""

    def __init__(self, acd_client, cache, buffer_size, timeout):
        self.acd_client = acd_client
        self.cache = cache
        self.files = defaultdict(lambda: WriteProxy.WriteStream(buffer_size, timeout))

    class WriteStream(object):
        """A WriteStream is a binary file-like object that is backed by a Queue.
        It will remember its current offset."""

        __slots__ = ('q', 'offset', 'error', 'closed', 'done', 'timeout')

        def __init__(self, buffer_size, timeout):
            self.q = Queue(maxsize=buffer_size)
            """a queue that buffers written blocks"""
            self.offset = 0
            """the beginning fpos"""
            self.error = False
            """whether the read or write failed"""
            self.closed = False
            self.done = Event()
            """done event is triggered when file is successfully read and transferred"""
            self.timeout = timeout

        def write(self, data: bytes):
            """Writes data into queue.
            :raises: FuseOSError on timeout"""

            if self.error:
                raise FuseOSError(errno.EREMOTEIO)
            try:
                self.q.put(data, timeout=self.timeout)
            except QueueFull:
                logger.error('Write timeout.')
                raise FuseOSError(errno.ETIMEDOUT)
            self.offset += len(data)

        def read(self, ln=0) -> bytes:
            """Returns as much byte data from queue as possible.
            Returns empty bytestring (EOF) if queue is empty and file was closed.
            :raises: IOError"""

            if self.error:
                raise IOError(errno.EIO, errno.errorcode[errno.EIO])

            if self.closed and self.q.empty():
                return b''

            b = [self.q.get()]
            self.q.task_done()
            while not self.q.empty():
                b.append(self.q.get())
                self.q.task_done()

            return b''.join(b)

        def flush(self):
            """Waits until the queue is emptied.
            :raises: FuseOSError"""

            while True:
                if self.error:
                    raise FuseOSError(errno.EREMOTEIO)
                if self.q.empty():
                    return
                sleep(1)

        def close(self):
            """Sets the closed flag to signal 'EOF' to the read function.
            Then, waits until :attr:`done` event is triggered.
            :raises: FuseOSError"""

            self.closed = True
            # prevent read deadlock
            self.q.put(b'')

            # wait until read is complete
            while True:
                if self.error:
                    raise FuseOSError(errno.EREMOTEIO)
                if self.done.wait(1):
                    return

    def write_n_sync(self, stream: WriteStream, node_id: str):
        """Try to overwrite file with id ``node_id`` with content from ``stream``.
        Triggers the :attr:`WriteStream.done` event on success.
        :param stream: a file-like object"""

        try:
            r = self.acd_client.overwrite_stream(stream, node_id)
        except (RequestError, IOError) as e:
            stream.error = True
            logger.error('Error writing node "%s". %s' % (node_id, str(e)))
        else:
            self.cache.insert_node(r)
            stream.done.set()

    def write(self, node_id, fh, offset, bytes_):
        """Gets WriteStream from defaultdict. Creates overwrite thread if offset is 0,
        tries to continue otherwise.
        :raises: FuseOSError: wrong offset or writing failed"""

        f = self.files[fh]

        if f.offset == offset:
            f.write(bytes_)
        else:
            f.error = True  # necessary?
            logger.error('Wrong offset for writing to fh %s.' % fh)
            raise FuseOSError(errno.ESPIPE)

        if offset == 0:
            t = Thread(target=self.write_n_sync, args=(f, node_id))
            t.daemon = True
            t.start()

    def flush(self, fh):
        f = self.files.get(fh)
        if f:
            f.flush()

    def release(self, fh):
        """:raises: FuseOSError"""
        f = self.files.get(fh)
        if f:
            try:
                f.close()
            except:
                raise
            finally:
                del self.files[fh]


class OneDriveFS(LoggingMixIn, Operations):
    def __init__(self, api, root, cache, conf, log=None):
        self.api, self.root, self.cache = api, root, cache
        self.block_size = conf.getint('fuse', 'block_size')

        self.log = log or logging.getLogger(
            '{}.{}'.format(__name__, self.__class__.__name__))

        self.handles = {}
        """map fh->item\n\n :type: dict"""
        self.fh = 1
        """file handle counter\n\n :type: int"""
        self.fh_lock = Lock()
        """lock for fh counter increment and handle dict writes"""
        self.rp = ReadProxy(self.api, conf.getint('read', 'open_chunk_limit'), conf.getint('read', 'timeout'), conf.getint('read', 'dl_chunk_size'))
        """collection of files opened for reading"""
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

    def open(self, path, flags):
        if (flags & os.O_APPEND) == os.O_APPEND:
            raise FuseOSError(errno.EFAULT)

        item = self._getitem(path)
        if not item:
            raise FuseOSError(errno.ENOENT)
        with self.fh_lock:
            self.fh += 1
            self.handles[self.fh] = item
        return self.fh

    # def create(self, path, mode, fi=None):
    #     full_path = self._full_path(path)
    #     return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)

    def read(self, path, length, offset, fh):
        """Read ```length`` bytes from ``path`` at ``offset``."""
        if fh:
            item = self.handles[fh]
        else:
            item = self._getitem(path)
        if not item:
            raise FuseOSError(errno.ENOENT)

        if item.size <= offset:
            return b''

        if item.size < offset + length:
            length = item.size - offset

        self.log.debug('Reading file %s', path)
        return self.rp.get(path, offset, length, item.size)

    # def write(self, path, buf, offset, fh):
    #     os.lseek(fh, offset, os.SEEK_SET)
    #     return os.write(fh, buf)

    # def flush(self, path, fh):
    #     return os.fsync(fh)

    def release(self, path, fh):
        if fh:
            item = self.handles[fh]
        else:
            item = self._getitem(path)
        if item:
            self.rp.release(path)
            with self.fh_lock:
                del self.handles[fh]
        else:
            raise FuseOSError(errno.ENOENT)

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
    print ('Paste this URL into your browser, approve the app\'s access.')
    print ('Copy everything in the address bar after "code=", and paste it below.')
    print (auth_url)
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

    FUSE(OneDriveFS(api, root='/', log=log, cache=items_cache, conf=cfg), optz.mountpoint, foreground=True)

if __name__ == '__main__':
    main()
