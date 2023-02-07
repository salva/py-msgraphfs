import os
import sys

import logging
#logging.basicConfig(level=logging.DEBUG)

import json
import configparser
import argparse
import pprint
import stat
import errno
import pyfuse3
import trio
import faulthandler
from pathlib import Path
from azure.identity import InteractiveBrowserCredential, ClientSecretCredential, TokenCachePersistenceOptions, AuthenticationRecord
import httpx
import datetime
import dateutil.parser
import tempfile
import math
import time

faulthandler.enable()
UID = os.geteuid()
GID = os.getegid()
BLKSIZE = 65536
graph_url = "https://graph.microsoft.com/v1.0"

# expire data after given seconds
expiration = 30

startup_time_ns = math.floor(time.time() * 1e9)

def bs(s):
    if s is None:
        return None
    return bytes(s, "utf-8")

def clean_name(s):
    if s is None:
        return None
    if "/" in s:
        s = s.replace("/", "_(slash)_")
    return bs(s)


def u8(b):
    if b is None:
        return None
    return b.decode("utf-8")

def date2epoch_ns(txt, alt=0):
    if txt is not None:
        return math.floor(dateutil.parser.isoparse(txt).timestamp() * 1e9)
    else:
        return alt

def attr2dict(st):
    return {'ino': st.st_ino,
            'generation': st.generation,
            'entry_timeout': st.entry_timeout,
            'attr_timeout': st.attr_timeout,
            'mode': st.st_mode,
            'omode': oct(st.st_mode),
            'nlink': st.st_nlink,
            'uid': st.st_uid,
            'gid': st.st_gid,
            'rdev': st.st_rdev,
            'size': st.st_size,
            'blksize': st.st_blksize,
            'blocks': st.st_blocks,
            'atime': st.st_atime_ns,
            'ctime': st.st_ctime_ns,
            'mtime': st.st_mtime_ns}

def flags2set(flags):
    s = []
    for f in "append async cloexec creat direct directory dsync excl largefile noatime noctty \
              nofollow nonblock ndelay path async tmpfile trunc rdonly wronly rdwr".split():
        n = "O_"+f.upper()
        try:
            value = getattr(os, n)
        except:
            logging.info(f"{n} not found in 'os' package")
        else:
            mask = os.O_ACCMODE if f in ('rdonly', 'wronly', 'rdwr') else value
            if (flags & mask) == value:
                s.append(n)
    return set(s)

class Node():
    def __init__(self, id, inode=0, drive=None, mode=0):
        self.id = id
        self.real_id = id
        self.drive = drive
        st = pyfuse3.EntryAttributes()
        self.st = st
        st.st_ino = inode
        st.generation = 0
        st.entry_timeout = 60
        st.attr_timeout = 60
        st.st_mode = mode
        st.st_uid = UID
        st.st_gid = GID
        st.st_rdev = 0
        st.st_size = 0
        st.st_ctime_ns = 0
        st.st_mtime_ns = 0
        st.st_atime_ns = 0

    async def populate(self, fs, res=None):
        if res is None:
            try:
                res = await fs._get(self.url())
            except:
                logging.exception("populate failed")
                raise pyfuse3.FUSEError(errno.EIO)
        self._populate(res)
        #logging.debug(f"Node is now {self.to_json()}")

    def _populate(self, res):
        self.real_id = res.get("id", self.id)
        st = self.st
        st.st_size = res.get("size", 0)
        st.st_ctime_ns = date2epoch_ns(res.get("createdDateTime"))
        st.st_mtime_ns = date2epoch_ns(res.get("lastModifiedDateTime"), st.st_ctime_ns)
        st.st_atime_ns = st.st_mtime_ns

    def is_file(self):
        return False

    def is_dir(self):
        return False

    def to_dict(self):
        r = {**self.__dict__, 'st': attr2dict(self.st)}
        r = {k: u8(v) if isinstance(v, bytes) else v for k, v in r.items()}
        if r["drive"] is not None:
            # print(f"Replacing object {r['drive']} for JSON dump")
            r["drive"] = r["drive"].id
        try:
            r["children"] = [u8(c) for c in r["children"].keys()]
        except:
            pass
        return r

    def to_json(self):
        return json.dumps(self.to_dict())

    def url(self, path=""):
        if self.drive is not None:
            return self.drive.item_url(self.id, path)
        logging.error(f"Can't generate URL for Node {self.id} (inode: {self.st.st_ino}) because drive is None")
        raise pyfuse3.FUSEError(errno.EIO)

    async def getattr(self, fs):
        await self.populate(fs)
        return self.st

class FileNode(Node):
    def __init__(self, **kwargs):
        super().__init__(mode=stat.S_IFREG | 0o600, **kwargs)

    def _populate(self, res):
        super()._populate(res)
        self.download_url = res.get("downloadUrl", None)

    def is_file(self):
        return True

class DirNode(Node):
    def __init__(self, children = None, **kwargs):
        super().__init__(mode= stat.S_IFDIR | 0o700, **kwargs)
        self.children = children

    def is_dir(self):
        return True

    async def mkdir(self, fs, name):
        raise fuse.FUSEError(EACCES)

class FolderNode(DirNode):
    _child_class = {}

    def _populate(self, res):
        super()._populate(res)
        self.child_count = res.get("folder", {}).get("childCount", 0)
        self.special_folder_name = bs(res.get("specialFolder", {}).get("name"))

    def url(self, path=""):
        return self.drive.item_url(self.id, path)

    def drive_for_items(self):
        return self.drive

    def children_url(self):
        return self.url("/children")

    async def _list_children(self, fs):
        res = await fs._get(self.children_url())
        return { bs(v["name"]): v for v in res["value"] }

    async def list(self, fs):
        if True: # if self.children is None:
            ls = await self._list_children(fs)
            self.children = {}
            for name, res in ls.items():
                logging.info(f"child_class: {self._child_class}")
                for entry, klass in self._child_class.items():
                    if entry in res:
                        logging.info(f"creating object of class {klass}")
                        node = await fs._alloc_or_populate_node_from_response(klass, res, drive=self.drive_for_items())
                        self.children[name] = node
                        break
                else:
                    logging.error(f"Can't handle value {json.dumps(res)}, keys: {list(self._child_class.keys())}")
        return self.children

    async def mkdir(self, fs, name):
        url = self.children_url()
        r = await fs._post_raw(url, data = { "name": u8(name),
                                             "folder": {},
                                             "@microsoft.graph.conflictBehavior": "fail" })
        if r.status_code == 201: # Created!
            node = await fs._alloc_or_populate_from_response(self._child_class["folder"], r.json(), drive=self.drive_for_items())
            if self.children is not None:
                self.children[name] = node
            return node.st
        if r.status_code == 409: # Conflict!
            raise pyfuse3.FUSEError(errno.EEXIST)
        else:
            logging.error(f"Unexpected response for mkdir: code: {r.status_code}")
            raise pyfuse3.FUSEError(errno.EIO) # Unhandled response

FolderNode._child_class["folder"] = FolderNode
FolderNode._child_class["file"] = FileNode

class DriveNode(FolderNode):
    def drive_for_items(self):
        return self

    def item_url(self, item_id, path=""):
        return f"{self.drive_url()}/items/{item_id}{path}"

    def drive_url(self):
        return f"/drives/{self.id}"

class MeNode(DriveNode):
    def drive_url(self):
        return f"/me/drive"

    def url(self, path=""):
        return f"/me/drive/root{path}"

class GroupNode(DriveNode):
    def drive_url(self):
        return f"/groups/{self.id}/drive"

    def children_url(self):
        return f"/groups/{self.id}/drive/root/children"

class GroupsNode(DriveNode):
    _child_class = { 'groupTypes': GroupNode }

    def url(self, path=""):
        return f"/groups{path}"

    def children_url(self):
        return "/groups"

    async def _list_children(self, fs):
        res = await fs._get(self.children_url())
        children = { clean_name(v["displayName"]): v for v in res["value"] }
        logging.info(f"Children: {children.keys()}")
        return children

    def item_url(self, item_id, path):
        return f"/groups/{item_id}{path}"

class SyntheticNode(DirNode):
    _children_decl = []

    async def populate(self, fs, res=None):
        pass

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.st.st_ctime_ns = startup_time_ns
        self.st.st_mtime_ns = startup_time_ns
        self.st.st_atime_ns = startup_time_ns

    async def list(self, fs):
        self.children = {}
        for name, id, klass in self._children_decl:
            self.children[name] = await fs._alloc_or_populate_node_from_id(klass, id)
        return self.children

class RootNode(SyntheticNode):
    _children_decl = [(b"me", ":me", MeNode),
                      (b"groups", ":groups", GroupsNode)]

class Handler():
    def __init__(self, node):
        self.node = node

    async def start(self, fs):
        pass

class FileHandler(Handler):
    def __init__(self, node, flags):
        super().__init__(node)
        self.flags = flags
        self.download_url = None

    async def start(self, fs):
        await super().start(fs)
        self.download_url = await fs._download_url(self.node)

    async def flush(self, fs):
        pass

    async def release(self, fs):
        pass

class RdFileHandler(FileHandler):
    async def read(self, fs, offset, size):
        r = await fs._get_raw(self.download_url, headers={"Range": f"bytes={offset}-{offset+size-1}"})
        return r.content

    async def write(self, *_):
        logging.error("Write access in RDONLY file handle attempted")
        raise pyfuse3.FUSEError(errno.EACCES)

class WrFileHandler(FileHandler):
    def __init__(self, node, flags):
        super().__init__(node, flags)
        self.upload_url = None
        self.local_fh = None
        self.append = False
        self.changed = False

    async def read(self, *_):
        logging.error("Read access in WRONLY file handle attempted")
        raise pyfuse3.FUSEError(errno.EACCES)

    async def start(self, fs):
        await super().start(fs)
        node = self.node
        self.upload_url = fs._node_url(node, "/content")
        if self.flags & os.O_APPEND:
            self.append = True # We actually ignore this and hope for the OS doing its dutties!
        self.local_fh = tempfile.NamedTemporaryFile(mode='w+b', delete=False)
        if node.st.st_size > 0:
            if (self.flags & os.O_TRUNC):
                (node, _) = await fs._put_empty_at_url(self.upload_url)
            else:
                await self._download_to_local(fs)

    async def write(self, fs, off, buffer):
        self.changed = True
        self.local_fh.seek(off)
        self.local_fh.write(buffer)
        return len(buffer)

    async def _download_to_local(self, fs):
        url = self.download_url
        async with fs._get_stream(url) as r:
            logging.info(f"GET streaming {url} --> status code: {r.status_code}, headers: {r.headers}")
            async for chunk in r.aiter_bytes():
                self.local_fh.write(chunk)

    async def flush(self, fs):
        if self.changed:
            self.changed = False
            self.local_fh.seek(0)
            return await self._upload_from_local(fs)

    async def release(self, fs):
        return await self.flush(fs)

    async def _upload_from_local(self, fs):
        async def gen(file):
            logging.info("upload_from_local generator started")
            file.seek(0)
            while True:
                data = file.read(16384)
                if data == b'':
                    logging.info("generator done generating data")
                    return
                logging.info(f"generator yielding {len(data)} bytes")
                yield data

        r = await fs._put_raw(self.upload_url, content = gen(self.local_fh))
        if r.status_code == 200:
            return r.json()
        raise pyfuse3.FUSEError(errno.EIO)

class RdWrFileHandler(WrFileHandler):
    async def read(self, fs, offset, size):
        self.local_fh.seek(offset)
        return self.local_fh.read(size)

accmode2class = { os.O_RDONLY: RdFileHandler,
                  os.O_WRONLY: WrFileHandler,
                  os.O_RDWR: RdWrFileHandler }

class DirHandler(Handler):
    pass

class GraphFS(pyfuse3.Operations):

    supports_dot_lookup = False
    enable_acl = False
    enable_writeback_cache = False

    def __init__(self, tenant, graph_token):
        super().__init__()
        self._tenant = tenant
        self._graph_token = graph_token
        self._last_inode = pyfuse3.ROOT_INODE
        self._fileno_max = 0
        self._filenos_available = [0]
        self._by_inode={}
        self._by_id={}
        self._open_files = {}
        self._open_dirs = {}
        self._client = httpx.AsyncClient()
        self._alloc_node(RootNode, ":root", inode=pyfuse3.ROOT_INODE)

    def _alloc_fileno(self):
        try:
            return self._filenos_available.pop()
        except:
            self._fileno_max += 1
            return self._fileno_max

    def _release_fileno(self, fileno):
        self._filenos_available.append(fileno)

    def _inode2node(self, inode):
        try:
            return self._by_inode[inode]
        except:
            raise pyfuse3.FUSEError(errno.ENOENT)

    def _alloc_inode(self):
        self._last_inode += 1
        return self._last_inode

    def _alloc_node(self, klass, id, inode=None, **kwargs):
        if inode is None:
            inode = self._alloc_inode()
        logging.info(f"inode {inode} allocated for node {id}, class: {klass}!")
        node = klass(id=id, inode=inode, **kwargs)
        self._by_inode[inode] = node
        self._by_id[id] = node
        return node

    async def _alloc_or_populate_node_from_id(self, klass, id, res=None, drive=None):
        if id in self._by_id:
            node = self._by_id[id]
        else:
            node = self._alloc_node(klass, id, drive=drive)
        if not isinstance(node, klass):
            logging.error(f"Node klass ({type(node)}) not as expected ({klass}).")
            raise pyfuse3.FUSEError(errno.EIO)
        await node.populate(self, res)
        return node

    async def _alloc_or_populate_node_from_response(self, klass, res, drive=None):
        id = res["id"]
        return await self._alloc_or_populate_node_from_id(klass, id, res=res, drive=drive)

    async def lookup(self, parent_inode, name, ctx=None):
        logging.info(f"lookup({parent_inode}, {name})")
        parent_node = self._inode2node(parent_inode)
        node = await self._lookup(parent_node, name)
        return await node.getattr(self)

    async def _lookup(self, parent_node, name):
        children = await parent_node.list(self)
        try:
            return children[name]
        except:
            raise pyfuse3.FUSEError(errno.ENOENT)

    async def getattr(self, inode, ctx=None):
        node = self._inode2node(inode)
        st = await node.getattr(self)
        logging.info(f"getattr({inode} [{node.id}]) --> {attr2dict(st)}")
        return st

    def _check_dir(self, node):
        if not node.is_dir():
            raise pyfuse3.FUSEError(errno.ENOTDIR)

    def _check_file(self, node):
        if not node.is_file():
            raise pyfuse3.FUSEError(errno.ENOTSUP)

    async def opendir(self, inode, ctx):
        node = self._inode2node(inode)
        self._check_dir(node)
        fileno = self._alloc_fileno()
        try:
            e = DirHandler(node)
            children = await node.list(self)
            e.entries = list(children.keys())
            logging.info(f"DirHandler created for {len(e.entries)} entries")
        except:
            logging.exception("opendir failed")
            self._filenos_available.append(fileno)
            raise
        self._open_dirs[fileno] = e
        return fileno

    async def readdir(self, fileno, start_id, token):
        e = self._open_dirs[fileno]
        top = len(e.entries)
        for ix in range(start_id, top):
            name = e.entries[ix]
            try:
                node = await self._lookup(e.node, name)
                st = await node.getattr(self)
                ok = pyfuse3.readdir_reply(token, name, st, ix+1)
                logging.info(f"called readdir cb for {name}, ix: {ix}  -> {ok}")
                if not ok:
                    return 0
            except:
                logging.exception(f"Lookup for entry {e.entries[ix]} in node {e.node} failed")
        return 1

    async def releasedir(self, fileno):
        self._open_dirs.pop(fileno)
        self._filenos_available.append(fileno)

    async def _download_url(self, node):
        self._check_file(node)
        try:
            if True or node.download_url is None:
                url = node.url("/content")
                r = await self._get_raw(url)
                if r.status_code == 302:
                    node.download_url = r.headers["Location"]
                    logging.info(f"Download URL for {node.id} is {node.download_url}")
            return node.download_url
        except:
            raise pyfuse3.FUSEError(errno.ENOENT)

    async def _put_empty_at_url(self, url):
        r = await self._put_raw(url, content=b'')
        if r.status_code in (200, 201): # Ok, Created!
            return self._alloc_or_populate_node_from_response(r.json())
        else:
            raise pyfuse3.FUSEError(errno.EIO)

    async def create(self, parent_inode, name, mode, flags, ctx):
        parent_node = self._inode2node(parent_inode)
        logging.info(f"create({parent_inode} [id: {parent_node.id}], name: {name}, mode: {oct(mode)}, flags: {hex(flags)} [{flags2set(flags)}])")
        url = self._node_url(parent_node, f":/{u8(name)}:/content")
        (_, node) = await self._put_empty_at_url(url)
        parent_node.children[name] = node
        logging.info(f"Created node: {node._to_json()}")
        fi = await self.open(node.st.st_ino, flags, ctx)
        return (fi, node.st)

    async def open(self, inode, flags, ctx):
        node = self._inode2node(inode)
        logging.info(f"open(inode: {inode} [id: {node.id}], flags: {flags2set(flags)})")
        klass = accmode2class[flags&os.O_ACCMODE]
        fh = klass(node, flags)
        try:
            await fh.start(self)
        except:
            logging.exception("start failed")
            raise
        fileno = self._alloc_fileno()
        self._open_files[fileno] = fh
        logging.info(f"open(inode: {inode}) succeeded")
        return pyfuse3.FileInfo(fh=fileno, direct_io=False, keep_cache=False)

    async def _open(self, node, flags):

        return fh

    async def read(self, fileno, offset, size):
        e = self._open_files[fileno]
        content = await e.read(self, offset, size)
        logging.info(f"read(fileno: {fileno}, offset: {offset}, size: {size}) --> {len(content)} bytes")
        return content

    async def write(self, fileno, offset, buffer):
         e = self._open_files[fileno]
         r = await e.write(self, offset, buffer)
         logging.info(f"write(fileno: {fileno}, offset: {offset}, buffer: {len(buffer)} bytes) --> {r} bytes")
         return r

    async def flush(self, fileno):
        logging.info(f"flush(fileno: {fileno})")
        e = self._open_files[fileno]
        r = await e.flush(self)
        if r:
            self._alloc_or_populate_node_from_response(r)
        pyfuse3.invalidate_inode(e.node.st.st_ino, attr_only=True)

    async def release(self, fileno):
        logging.info(f"release({fileno})")
        e = self._open_files.pop(fileno)
        r = await e.release(self)
        if r:
            self._alloc_or_populate_node_from_response(r)
        self._filenos_available.append(fileno)
        pyfuse3.invalidate_inode(e.node.st.st_ino, attr_only=True)

    async def mkdir(self, parent_inode, name, mode, ctx):
        parent_node = self._inode2node(parent_inode)
        await parent_node.mkdir(fs, name)

    async def rmdir(self, parent_inode, name, ctx):
        parent_node = self._inode2node(parent_inode)
        node = await self._lookup(parent_node, name)
        self._check_dir(node)
        if node.child_count:
            raise pyfuse3.FUSEError(errno.ENOTEMPTY)
        if node.special_folder is not None:
            raise pyfuse3.FUSEError(errno.EPERM)
        url = self._node_url(node)
        r = await self._delete_raw(url)
        if r.status_code == 204:
            del parent_node.children[name]
            return 0
        logging.error(f"response code: {r.status_code}\n{u8(r.content)}")
        raise pyfuse3.FUSEError(errno.EIO)

    async def unlink(self, parent_inode, name, ctx):
        parent_node = self._inode2node(parent_inode)
        node = await self._lookup(parent_node, name)
        url = self._node_url(node)
        r = await self._delete_raw(url)
        if r.status_code == 204:
            del parent_node.children[name]
            return 0
        logging.error(f"response code: {r.status_code}\n{u8(r.content)}")
        raise pyfuse3.FUSEError(errno.EIO)

    async def rename(self,
                     parent_inode_old, name_old,
                     parent_inode_new, name_new,
                     flags, ctx):

        # TODO: handle correctly the case where parent_new is :me root
        parent_node_old = self._inode2node(parent_inode_old)
        node = await self._lookup(parent_node_old, name_old)
        parent_node_new = self._inode2node(parent_inode_new)

        url = self._node_url(node, "?@microsoft.graph.conflictBehavior=replace")
        r = await self._patch_raw(url, data={ "parentReference": { "id": parent_node_new.id },
                                              "name": u8(name_new) })
        if r.status_code == 200:
            node = parent_node_old.children.pop(name_old)
            parent_node_new.children[name_new] = node
            await self._fill_attr(node)
            return 0
        raise pyfuse3.FUSEError(errno.EIO)

    async def _get(self, url, **kwargs):
        r = await self._get_raw(url, **kwargs)
        if r.status_code < 300:
            return r.json()
        if r.status_code == 403:
            raise pyfuse3.FUSEError(errno.EACCES)
        logging.error("GET {url} failed: {r.status_code}")
        raise pyfuse3.FUSEError(errno.EIO)

    def _mkurl(self, url):
        if url.startswith('/'):
            return graph_url + url
        return url

    def _get_raw(self, url, headers = {}, **kwargs): # implicit async!
        headers = { "Authorization": f"Bearer {self._graph_token}", **headers }
        url = self._mkurl(url)
        logging.info(f"GET {url}")
        return self._client.get(url, headers=headers, **kwargs)

    async def _post(self, url, **kwargs):
        r = await self._post_raw(url, **kwargs)
        return r.json()

    async def _send_raw(self, method, url, content=None, data=None, headers={}, **kwargs):
        headers = { "Authorization": f"Bearer {self._graph_token}", **headers }
        if content is None:
            content = json.dumps(data)
            headers["Content-Type"]="application/json"
        else:
            headers.setdefault("Content-Type", "application/octet-stream")
        url = self._mkurl(url)
        r = await method(url, content=content, headers=headers, **kwargs)
        logging.info(f"SEND[*] {url} --> status code: {r.status_code}, headers: {r.headers}, content:\n{u8(r.content)}")
        return r

    def _post_raw(self, url, **kwargs): # Implicit async!
        return self._send_raw(self._client.post, url, **kwargs)

    def _patch_raw(self, url, **kwargs): # Implicit async!
        return self._send_raw(self._client.patch, url, **kwargs)

    def _put_raw(self, url, **kwargs):
        return self._send_raw(self._client.put, url, **kwargs)

    def _options_raw(self, url, headers={}, **kwargs):
        headers = { "Authorization": f"Bearer {self._graph_token}", **headers }
        url = self._mkurl(url)
        return self._client.options(url, headers=headers, **kwargs)

    async def _delete_raw(self, url, headers={}, **kwargs):
        headers = { "Authorization": f"Bearer {self._graph_token}", **headers }
        url = self._mkurl(url)
        r = await self._client.delete(url, headers=headers, **kwargs)
        logging.info(f"DELETE {url} --> status code: {r.status_code}, content:\n{u8(r.content)}")
        return r

    def _get_stream(self, url, headers={}, **kwargs):
        headers = { "Authorization": f"Bearer {self._graph_token}", **headers }
        url = self._mkurl(url)
        logging.info(f"GET stream {url}")
        stream = self._client.stream('GET', url, headers=headers, **kwargs)
        logging.info(f"stream: {stream}")
        return stream

def init_logging(debug=False):
    formatter = logging.Formatter('%(asctime)s.%(msecs)03d %(threadName)s: '
                                  '[%(name)s] %(message)s', datefmt="%Y-%m-%d %H:%M:%S")
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    root_logger = logging.getLogger()
    if debug:
        handler.setLevel(logging.DEBUG)
        root_logger.setLevel(logging.DEBUG)
    else:
        handler.setLevel(logging.INFO)
        root_logger.setLevel(logging.INFO)
    root_logger.addHandler(handler)

def parse_args():
    '''Parse command line'''

    parser = argparse.ArgumentParser()

    parser.add_argument('tenant', type=str,
                        help='Where to mount the file system')
    parser.add_argument('mountpoint', type=str,
                        help='Where to mount the file system')
    parser.add_argument('--debug', action='store_true', default=False,
                        help='Enable debugging output')
    parser.add_argument('--debug-fuse', action='store_true', default=False,
                        help='Enable FUSE debugging output')
    return parser.parse_args()

def load_config(tenant):
    config_fn = Path.home() / ".config/msgraphfs.ini"
    if not config_fn.is_file():
        raise Exception(f"Configuration file {config_fn} not found")

    config = configparser.ConfigParser()
    config.read(config_fn)
    if tenant not in config:
        raise Exception(f"Tenant {tenant} not found in configuration file")
    config = dict(config[tenant])
    config["tenant"] = tenant
    return config

def authenticate(config):
    ar_fn = Path.home() / f".config/msgraphfs/{config['tenant']}.ini"
    ar_cfg = configparser.ConfigParser()
    ar_cfg.optionxform = str
    try:
        ar_cfg.read(ar_fn)
        ar = AuthenticationRecord.deserialize(json.dumps(dict(ar_cfg["Authentication Record"])))
    except:
        logging.exception("Couldn't load authentication record")
        ar = None

    redirect_uri = f"http://localhost:{config['authentication_callback_port']}"
    cred = InteractiveBrowserCredential(tenant_id=config["tenant_id"],
                                        client_id=config["application_id"],
                                        client_credential=config["application_secret"],
                                        redirect_uri=redirect_uri,
                                        cache_persistence_options=TokenCachePersistenceOptions(),
                                        authentication_record=ar)
    ar = cred.authenticate(scopes=["https://graph.microsoft.com/.default"])
    try:
        ar_cfg["Authentication Record"] = json.loads(ar.serialize())
        ar_fn.parent.mkdir(exist_ok=True, parents=True)
        with open(ar_fn, 'w') as f:
            ar_cfg.write(f)
        return cred
    except:
        logging.exception("Unable to save authentication record")

def main():
    options = parse_args()
    init_logging(options.debug)

    tenant = options.tenant
    config = load_config(tenant)
    cred = authenticate(config)

    graph_fs = GraphFS(tenant, cred.get_token("https://graph.microsoft.com/.default").token)
    fuse_options = set(pyfuse3.default_options)
    fuse_options.add('fsname=msgraphfs')
    if options.debug_fuse:
        fuse_options.add('debug')
    pyfuse3.init(graph_fs, options.mountpoint, fuse_options)
    try:
        trio.run(pyfuse3.main)
    except:
        pyfuse3.close(unmount=False)
        raise

    pyfuse3.close()


if __name__ == '__main__':
    main()
