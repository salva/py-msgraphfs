import os
import sys

import logging
# logging.basicConfig(level=logging.DEBUG)

import json
import configparser
import argparse
import stat
import errno
import pyfuse3
import trio
import faulthandler
from pathlib import Path
from azure.identity import (InteractiveBrowserCredential,
                            TokenCachePersistenceOptions,
                            AuthenticationRecord)
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
external_expiration = 5
expiration = 15

startup_time_ns = math.floor(time.time() * 1e9)

PRIVATE_DIR = Path.home() / ".msgraphfs"

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

def date2ns(txt, alt=0):
    if txt is not None:
        return math.floor(dateutil.parser.isoparse(txt).timestamp() * 1e9)
    else:
        return alt

def _init_blocks(st):
    st.st_blksize = BLKSIZE
    st.st_blocks = (st.st_size + BLKSIZE - 1) // BLKSIZE

def gen_thrower(error_name):
    error_code = getattr(errno, error_name)

    def thrower():
        try:
            raise pyfuse3.FUSEError(error_code)
        except:
            logging.debug(f"Error {error_name}", exc_info=True)
            raise
    return thrower

for error_name in ('EIO', 'EACCES', 'EISDIR', 'ENOTDIR', 'EBADF',
                   'ENOSYS', 'ENOENT', 'ENOTEMPTY', 'ENOENT', 'ENOTSUP'):
    globals()[error_name] = gen_thrower(error_name)

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
            logging.error(f"{n} not found in 'os' package")
            raise
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
        self.expiration = 0
        st = pyfuse3.EntryAttributes()
        self._st = st
        st.st_ino = inode
        st.generation = 0
        st.entry_timeout = external_expiration
        st.attr_timeout = external_expiration
        st.st_mode = mode
        st.st_uid = UID
        st.st_gid = GID
        st.st_rdev = 0
        st.st_size = 0
        st.st_ctime_ns = 0
        st.st_mtime_ns = 0
        st.st_atime_ns = 0
        st.st_blocks = 0
        st.st_blksize = BLKSIZE

    def inode(self):
        return self._st.st_ino

    async def populate(self, fs, res=None, force=False):
        if res is None:
            if force or self.expiration < time.time():
                res = await fs._get_as_json(self.url())
            else:
                return
        self._populate(fs, res)

    def _populate(self, fs, res):
        self.expiration = time.time() + expiration
        self.real_id = res.get("id", self.id)
        st = self._st
        st.st_size = res.get("size", 0)
        st.st_ctime_ns = date2ns(res.get("createdDateTime"))
        st.st_mtime_ns = date2ns(res.get("lastModifiedDateTime"), st.st_ctime_ns)
        st.st_atime_ns = st.st_mtime_ns
        _init_blocks(st)

    def is_file(self):
        return False

    def is_dir(self):
        return False

    def ensure_file(self):
        if not self.is_file():
            EISDIR()

    def ensure_dir(self):
        if not self.is_dir():
            ENOTDIR()

    def to_json(self):
        r = {**self.__dict__, 'st': attr2dict(self._st)}
        r = {k: u8(v) if isinstance(v, bytes) else v for k, v in r.items()}
        if r["drive"] is not None:
            r["drive"] = r["drive"].id
        if r["children"] is not None:
            r["children"] = [u8(c) for c in r["children"].keys()]
        return json.dumps(r)

    def url(self, path=""):
        if self.drive is not None:
            return self.drive.item_url(self.id, path)
        logging.error(f"Can't generate URL for Node {self.id} (inode: {self._st.st_ino}) because drive is None")
        EIO()

    async def getattr(self, fs):
        await self.populate(fs)
        return self._st

    async def mkdir(self, fs, name):
        ENOTDIR()

    async def create(self, fs, name):
        ENOTDIR()

    async def lookup(self, fs, name):
        ENOTDIR()

    async def open(self, fs):
        EISDIR()

    async def setattr(self, fs, attr, fields):
        if fields.update_mtime:
            mtime = math.floor(attr.st_mtime_ns / 1e9)
        else:
            mtime = math.floor(time.time())
        mtime_iso8601 = datetime.datetime.fromtimestamp(mtime).strftime('%Y-%m-%dT%H:%M:%SZ')

        res = await fs._patch_as_json(self.url(),
                                      data = { "lastModifiedDateTime": mtime_iso8601 })
        self._populate(fs, res)

    async def unlink(self, fs):
        EISDIR()

    async def rmdir(self, fs):
        ENOTDIR()

    async def delete(self, fs):
        url = self.url()
        res = await fs._delete(url, accepted_codes=[204])

    async def move(self, fs, new_parent, new_name):
        url = self.url("?@microsoft.graph.conflictBehavior=replace")
        res = await fs._patch_as_json(url, data={ "parentReference": { "id": new_parent.real_id },
                                                  "name": u8(new_name) })
        self._populate(fs, res)

class FileNode(Node):
    def __init__(self, **kwargs):
        super().__init__(mode=stat.S_IFREG | 0o600, **kwargs)
        self._local_fh = None
        self._writers = 0
        self._changed = 0

    def _populate(self, fs, res):
        super()._populate(fs, res)
        self._download_url = res.get("downloadUrl", None)
        if self._local_fh is not None:
            self._patch_attrs_from_local()

    def is_file(self):
        return True

    def _patch_attrs_from_local(self):
        if self._local_fh is None:
            EIO()
        st = self._st
        local_st = os.fstat(self._local_fh.fileno())
        st.st_size = local_st.st_size
        st.st_mtime_ns = math.floor(local_st.st_mtime*1e9)
        st.st_atime_ns = st.st_mtime_ns
        _init_blocks(st)

    async def getattr(self, fs):
        if self._local_fh is None:
            return await super().getattr(fs)
        if self._st.st_ctime_ns == 0:
            await self.populate(fs)
        self._patch_attrs_from_local()
        return self._st

    async def _init_local_fh(self, fs, flags):
        # TODO: set a semaphore here!
        trunc = (flags & os.O_TRUNC) != 0
        if self._local_fh is None:
            self._local_fh = tempfile.NamedTemporaryFile(mode='w+b', delete=False)
            if self._st.st_size > 0 and not trunc:
                await self._download_to_local(fs)
                self._changed = False
            else:
                self._changed = True
            await self._remote_truncate(fs)
        elif trunc:
            os.truncate(self._local_fh.fileno(), 0)

    async def download_url(self, fs):
        if self._download_url is None:
            url = self.url("/content")
            res = await fs._get(url, accepted_codes=[302])
            if "Location" in res.headers:
                self._download_url = res.headers["Location"]
            else:
                EIO()
        return self._download_url

    async def _download_to_local(self, fs):
        url = await self.download_url(fs)
        async with fs._get_stream(url) as res:
            async for chunk in res.aiter_bytes():
                self._local_fh.write(chunk)

    async def upload_url(self, fs):
        return self.url("/content")

    async def _upload_from_local(self, fs):
        url = await self.upload_url(fs)
        async def gen(file):
            file.seek(0)
            while True:
                data = file.read(16384)
                if data == b'':
                    return
                yield data

        res = await fs._put_as_json(url, content = gen(self._local_fh))
        logging.info(f"File {self.id} uploaded")
        return res

    async def open(self, fs, flags):
        logging.debug(f"open({self.id} [inode: {self._st.st_ino}], flags: {flags2set(flags)})")
        if (flags & os.O_ACCMODE) != os.O_RDONLY:
            await self._init_local_fh(fs, flags)
            self._writers += 1
        klass = accmode2class[flags&os.O_ACCMODE]
        fh = klass(self, flags)
        return fh

    async def write(self, fs, off, buffer, append=False):
        if self._local_fh is None:
            EBADF()
        self._changed = True
        # TODO: sem here!
        if append:
            self._local_fh.seek(0, 2)
        else:
            self._local_fh.seek(off)
        self._local_fh.write(buffer)

    async def read(self, fs, off, size):
        if self._local_fh is None:
            # File is not cached locally
            url = await self.download_url(fs)
            res = await fs._get(url, headers={"Range": f"bytes={off}-{off+size-1}"})
            return res.content
        else:
            # TODO: sem here!
            self._local_fh.seek(off)
            return self._local_fh.read(size)

    async def flush(self, fs):
        if self._changed:
            self._changed = False
            res = await self._upload_from_local(fs)
            self._populate(fs, res)

    async def release(self, fs):
        await self.flush(fs)
        self._writers -= 1
        if self._writers <= 0:
            os.unlink(self._local_fh.name)
            self._local_fh = None

    async def setattr(self, fs, attr, fields):
        if fields.update_size:
            if attr.st_size == 0:
                await self.truncate(fs)
            else:
                ENOSYS()
        return await super().setattr(fs, attr, fields)

    async def truncate(self, fs):
        await self._remote_truncate(self, fs)
        if self._local_fh is not None:
            self._local_fh.truncate(0)
            self._changed = True

    async def _remote_truncate(self, fs):
        res = await fs._put_as_json(self.url("/content"), content=b"")
        self._populate(fs, res)

class DirNode(Node):
    def __init__(self, children = None, **kwargs):
        super().__init__(mode= stat.S_IFDIR | 0o700, **kwargs)
        self.children = children
        self.children_expiration = time.time() + expiration

    def is_dir(self):
        return True

    async def lookup(self, fs, name):
        children = await self.list(fs)
        try:
            return children[name]
        except:
            ENOENT()

class FolderNode(DirNode):
    _child_class = {}

    def _populate_children(self, fs, res, incremental=False):
        unwrapped = self._children_values_in_response(res)
        if incremental:
            if self.children is None:
                return
        else:
            if unwrapped is None:
                self.children = None
                self.children_expiration = 0
                return
            self.children = {}
            self.children_expiration = time.time() + expiration

        for name, value in unwrapped.items():
            child = self._unpack_child(fs, value)
            child._populate(fs, value)
            self.children[name] = child

    def _populate(self, fs, res):
        super()._populate(fs, res)
        self._child_count = res.get("folder", {}).get("childCount", 0)
        self.special_folder_name = bs(res.get("specialFolder", {}).get("name"))
        incremental = "@odata.nextLink" in res
        self._populate_children(fs, res, incremental=incremental)

    def url(self, path=""):
        return self.drive.item_url(self.id, path)

    def drive_for_items(self):
        return self.drive

    def children_url(self):
        return self.url("/children")

    async def child_count(self, fs):
        await self.populate(fs, force=True)
        logging.debug(f"Requested child count: {self._child_count}")
        return self._child_count

    def _children_values_in_response(self, res):
        if "value" in res:
            return { bs(v["name"]): v for v in res["value"] }
        return None

    def _unpack_child(self, fs, value):
        for entry, klass in self._child_class.items():
            if entry in value:
                return fs._alloc_or_populate_node_from_response(klass, value, drive=self.drive_for_items())
        logging.error(f"Can't handle value {json.dumps(value)}, keys: {list(self._child_class.keys())}, ignoring issue!")

    async def list(self, fs):
        now = time.time()
        if self.children is None or self.children_expiration < now:
            if self.children is None:
                logging.debug(f"Loading directory {self.id}")
            else:
                logging.debug(f"Directory expired {self.id} exp: {self.children_expiration}, now: {now}")

            res = await fs._get_as_json(self.children_url())
            self._populate_children(fs, res)
            while "@odata.nextLink" in res:
                logging.debug(f"Directory listing continues at {res['@odata.nextLink']}")
                res = await fs._get_as_json(res["@odata.nextLink"])
                self._populate_children(fs, res, incremental=True)
        else:
            logging.debug(f"Directory listing {self.id} is still recent")
        return self.children

    async def mkdir(self, fs, name):
        url = self.children_url()
        res = await fs._post_as_json(url,
                                     data={ "name": u8(name),
                                            "folder": {},
                                            "@microsoft.graph.conflictBehavior": "fail" },
                                     accepted_codes=[201])
        node = fs._alloc_or_populate_node_from_response(self._child_class["folder"],
                                                        res, drive=self.drive_for_items())
        self._receive_child(name, node)
        return node

    async def create(self, fs, name):
        res = await fs._put_as_json(self.url(f":/{u8(name)}:/content"),
                                    content=b"")
        node = fs._alloc_or_populate_node_from_response(self._child_class['file'],
                                                        res,
                                                        drive=self.drive_for_items())
        self._receive_child(name, node)
        logging.debug(f"New empty file created inside {self.id}")
        return node

    async def delete_child(self, fs, name, child):
        logging.debug(f"Deleting node of class {type(child)}")
        await child.delete(fs)
        self._forget_child(name, child)

    def _forget_child(self, name, child):
        try:
            del self.children[name]
        except:
            logging.exception("Object just deleted from directory not found in children list, ignoring it!")
        self.expiration = 0

    async def unlink(self, fs, name):
        child = await self.lookup(fs, name)
        child.ensure_file()
        await self.delete_child(fs, name, child)

    async def rmdir(self, fs, name):
        child = await self.lookup(fs, name)
        child.ensure_dir()
        child_count = await child.child_count(fs)
        if child_count != 0:
            ENOTEMPTY()
        await self.delete_child(fs, name, child)

    def _receive_child(self, name, child):
        if self.children is not None:
            self.children[name] = child
        self.expiration = 0

    async def rename(self, fs, old_name, new_parent_node, new_name):
        new_parent_node.ensure_dir()
        if self.drive_for_items() is not new_parent_node.drive_for_items():
            EXDEV()
        child = await self.lookup(fs, old_name)
        await child.move(fs, new_parent_node, new_name)
        self._forget_child(old_name, child)
        new_parent_node._receive_child(new_name, child)

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

    def _children_values_in_response(self, res):
        return { clean_name(v["displayName"]): v for v in res["value"] }

    def item_url(self, item_id, path):
        return f"/groups/{item_id}{path}"

class SyntheticNode(DirNode):
    _children_decl = []

    async def populate(self, fs, res=None):
        pass

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._st.st_ctime_ns = startup_time_ns
        self._st.st_mtime_ns = startup_time_ns
        self._st.st_atime_ns = startup_time_ns

    async def list(self, fs):
        if self.children is None:
            self.children = {}
            self.chidren_expiration = sys.maxsize
            for name, id, klass in self._children_decl:
                self.children[name] = fs._alloc_or_populate_node_from_id(klass, id)
        return self.children

class RootNode(SyntheticNode):
    _children_decl = [(b"me", ":me", MeNode),
                      (b"groups", ":groups", GroupsNode)]

class Handler():
    def __init__(self, node):
        self.node = node

    async def start(self, fs):
        pass

    async def flush(self, fs):
        pass

    async def release(self, fs):
        pass

    async def write(self, *_):
        logging.error("Write access in RDONLY file handle attempted")
        EACCES()

    async def read(self, *_):
        logging.error("Read access in WRONLY file handle attempted")
        EACCES()

class FileHandler(Handler):
    def __init__(self, node, flags):
        super().__init__(node)
        self.flags = flags
        self.append = (flags & os.O_APPEND) != 0

class RdFileHandler(FileHandler):
    async def read(self, fs, off, size):
        return await self.node.read(fs, off, size)

class WrFileHandler(FileHandler):
    async def write(self, fs, off, buffer):
        await self.node.write(fs, off, buffer, append=self.append)
        return len(buffer)

    async def flush(self, fs):
        await self.node.flush(fs)

    async def release(self, fs):
        await self.node.release(fs)

class RdWrFileHandler(WrFileHandler):
    def read(self, fs, off, size): # implicit async!
        return self.node.read(fs, off, size)

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
        self._handler_by_fileno = {}
        self._client = httpx.AsyncClient()
        self._alloc_node(RootNode, ":root", inode=pyfuse3.ROOT_INODE)

    def _alloc_fileno(self):
        try:
            return self._filenos_available.pop()
        except:
            self._fileno_max += 1
            return self._fileno_max

    def _register_handler(self, fh):
        fileno = self._alloc_fileno()
        self._handler_by_fileno[fileno] = fh
        logging.debug(f"fh {fh} registered with number {fileno}")
        return fileno

    def _release_fileno(self, fileno):
        self._filenos_available.append(fileno)

    def _inode2node(self, inode):
        try:
            return self._by_inode[inode]
        except:
            ENOENT()

    def _fileno2handler(self, fileno):
        try:
            return self._handler_by_fileno[fileno]
        except:
            ENOENT()

    def _alloc_inode(self):
        self._last_inode += 1
        return self._last_inode

    def _alloc_node(self, klass, id, inode=None, **kwargs):
        if inode is None:
            inode = self._alloc_inode()
        node = klass(id=id, inode=inode, **kwargs)
        logging.debug(f"inode {inode} allocated for node {id} ({node.__class__.__name__})")
        self._by_inode[inode] = node
        self._by_id[id] = node
        return node

    def _alloc_or_populate_node_from_id(self, klass, id, res=None, drive=None):
        if id in self._by_id:
            node = self._by_id[id]
        else:
            node = self._alloc_node(klass, id, drive=drive)
        if not isinstance(node, klass):
            logging.error(f"Node klass ({type(node).__name__}) not as expected ({klass.__name__}).")
            EIO()
        return node

    def _alloc_or_populate_node_from_response(self, klass, res, drive=None):
        id = res["id"]
        return self._alloc_or_populate_node_from_id(klass, id, res=res, drive=drive)

    async def lookup(self, parent_inode, name, ctx=None):
        logging.info(f"lookup({parent_inode}, {name})")
        parent_node = self._inode2node(parent_inode)
        node = await parent_node.lookup(self, name)
        return await node.getattr(self)

    async def getattr(self, inode, ctx=None):
        node = self._inode2node(inode)
        st = await node.getattr(self)
        logging.info(f"getattr({inode} [{node.id}]) --> {attr2dict(st)}")
        return st

    def _check_dir(self, node):
        if not node.is_dir():
            ENOTDIR()

    def _check_file(self, node):
        if not node.is_file():
            ENOTSUP()

    async def opendir(self, inode, ctx):
        node = self._inode2node(inode)
        self._check_dir(node)
        dh = DirHandler(node)
        children = await node.list(self)
        dh.entries = list(children.keys())
        dirno = self._register_handler(dh)
        logging.debug(f"DirHandler at {node.id} [inode: {inode}] created with number {dirno} with {len(dh.entries)} entries")
        return dirno

    async def readdir(self, dirno, start_id, token):
        dh = self._fileno2handler(dirno)
        for ix in range(start_id, len(dh.entries)):
            name = dh.entries[ix]
            try:
                node = await dh.node.lookup(self, name)
                st = await node.getattr(self)
                ok = pyfuse3.readdir_reply(token, name, st, ix+1)
                if not ok:
                    return False
            except:
                logging.exception(f"Lookup for entry {dh.entries[ix]} in node {dh.node.id} failed, ignoring it")
        return True

    async def releasedir(self, dirno):
        dh = self._fileno2handler(dirno)
        self._handler_by_fileno.pop(dirno)
        self._filenos_available.append(dirno)

    async def setattr(self, inode, attr, fields, fileno, ctx):
        if fileno is None:
            node = self._inode2node(inode)
        else:
            fh = self._fileno2handler(fileno)
            node = fh.node
        await node.setattr(self, attr, fields)
        return await node.getattr(self)

    async def create(self, parent_inode, name, mode, flags, ctx):
        parent_node = self._inode2node(parent_inode)
        node = await parent_node.create(self, name)
        fi = await self.open(node.inode(), flags, ctx)
        attr = await node.getattr(self)
        return (fi, attr)

    async def open(self, inode, flags, ctx):
        node = self._inode2node(inode)
        fh = await node.open(self, flags)
        fileno = self._register_handler(fh)
        logging.info(f"open {node.id} [inode: {inode}] succeeded, fh: {fh}, fileno: {fileno}")
        return pyfuse3.FileInfo(fh=fileno, direct_io=False, keep_cache=False)

    async def read(self, fileno, off, size):
        fh = self._fileno2handler(fileno)
        content = await fh.read(self, off, size)
        logging.info(f"read(fileno: {fileno} [fh: {fh}], off: {off}, size: {size}) --> {len(content)} bytes")
        return content

    async def write(self, fileno, off, buffer):
         fh = self._fileno2handler(fileno)
         logging.info(f"writing fileno: {fileno}, fh: {fh}, off: {off}, buffer: {len(buffer)} bytes")
         await fh.write(self, off, buffer)
         return len(buffer)

    async def flush(self, fileno):
        logging.info(f"flush(fileno: {fileno})")
        fh = self._fileno2handler(fileno)
        await fh.flush(self)
        attr = await fh.node.getattr(self)
        pyfuse3.invalidate_inode(fh.node.inode(), attr_only=True)

    async def release(self, fileno):
        logging.info(f"release({fileno})")
        fh = self._fileno2handler(fileno)
        await fh.release(self)
        pyfuse3.invalidate_inode(fh.node.inode(), attr_only=True)
        self._handler_by_fileno.pop(fileno)
        self._filenos_available.append(fileno)

    async def mkdir(self, parent_inode, name, mode, ctx):
        logging.info(f"mkdir(parent_inode: {parent_inode}, name: {name})")
        parent_node = self._inode2node(parent_inode)
        child = await parent_node.mkdir(self, name)
        return await child.getattr(self)

    async def rmdir(self, parent_inode, name, ctx):
        logging.info(f"rmdir(parent_inode: {parent_inode}, name: {name})")
        parent_node = self._inode2node(parent_inode)
        node = await parent_node.rmdir(self, name)

    async def rename(self,
                     old_parent_inode, old_name,
                     new_parent_inode, new_name,
                     flags, ctx):
        logging.info(f"rename(old_parent_inode: {old_parent_inode}, old_name: {old_name}, new_parent_inode: {new_parent_inode} new_name: {new_name})")
        old_parent_node = self._inode2node(old_parent_inode)
        new_parent_node = self._inode2node(new_parent_inode)
        await old_parent_node.rename(self, old_name, new_parent_node, new_name)

    async def unlink(self, parent_inode, name, ctx):
        logging.info(f"unlink(parent_inode: {parent_inode}, name: {name})")
        parent_node = self._inode2node(parent_inode)
        await parent_node.unlink(self, name)

    def _get_as_json(self, url, **kwargs): # Implicit async!
        return self._send_as_json('get', url, **kwargs)

    def _get(self, url, **kwargs): # implicit async!
        return self._send('get', url, **kwargs)

    def _post_as_json(self, url, **kwargs): # Implicit async!
        return self._send_as_json('post', url, **kwargs)

    def _post(self, url, **kwargs): # Implicit async!
        return self._send('post', url, **kwargs)

    def _patch_as_json(self, url, **kwargs):
        return self._send_as_json('patch', url, **kwargs)

    def _patch(self, url, **kwargs): # Implicit async!
        return self._send('patch', url, **kwargs)

    def _put_as_json(self, url, **kwargs): # Implicit async!
        return self._send_as_json('put', url, **kwargs)

    def _put(self, url, **kwargs): # implicit async!
        return self._send('put', url, **kwargs)

    def _delete_as_json(self, url, **kwargs): # Implicit async!
        return self._send_as_json('delete', url, **kwargs)

    def _delete(self, url, **kwargs): # implicit async!
        return self._send('delete', url, **kwargs)

    async def _send_as_json(self, method, url, **kwargs):
        res = await self._send(method, url, **kwargs)
        return res.json()

    def _mkurl(self, url):
        if url.startswith('/'):
            return graph_url + url
        return url

    async def _send(self, method, url, accepted_codes=None, data=None, headers={}, **kwargs):
        headers = { "Authorization": f"Bearer {self._graph_token}", **headers }
        if data is not None:
            kwargs["content"] = json.dumps(data)
            headers["Content-Type"]="application/json"
        elif "content" in kwargs:
            headers.setdefault("Content-Type", "application/octet-stream")
        url = self._mkurl(url)
        call = getattr(self._client, method)
        res = await call(url, headers=headers, **kwargs)
        if accepted_codes is None:
            ok = res.status_code < 300
        else:
            ok = res.status_code in accepted_codes
        if ok:
            return res
        logging.error(f"HTTP request {method} {url} failed, code: {res.status_code}")
        if res.status_code == 403:
            EACCES()
        logging.debug(f"HTTP request headers: {res.headers}, text: {res.text}")
        EIO()

    def _get_stream(self, url, headers={}, **kwargs):
        logging.debug(f"GET (stream) {url}")
        headers = { "Authorization": f"Bearer {self._graph_token}", **headers }
        url = self._mkurl(url)
        return self._client.stream('GET', url, headers=headers, **kwargs)

def init_logging(log_fn=None, debug=False):
    if log_fn is not None:
        Path(log_fn).parent.mkdir(exist_ok=True, parents=True)

    logging.basicConfig(filename=log_fn,
                        level = logging.DEBUG if debug else logging.WARNING,
                        format = '%(levelname)s %(asctime)s.%(msecs)03d %(threadName)s: [%(name)s] %(message)s',
                        datefmt="%Y-%m-%d %H:%M:%S")

def parse_args():
    '''Parse command line'''

    parser = argparse.ArgumentParser()

    parser.add_argument('tenant', type=str,
                        help='Where to mount the file system')
    parser.add_argument('mountpoint', type=str, nargs='?',
                        help='Where to mount the file system')
    parser.add_argument('-d', '--debug', action='store_true', default=False,
                        help='Enable debugging output')
    parser.add_argument('-D', '--debug-fuse', action='store_true', default=False,
                        help='Enable FUSE debugging output')
    parser.add_argument('-f', '--foreground', action='store_true', default=False,
                        help='Run file system process in the foreground')
    return parser.parse_args()

def load_config(tenant):
    config_fn = PRIVATE_DIR / "msgraphfs.ini"
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
    ar_fn = PRIVATE_DIR / f"sessions/{config['tenant']}.ini"
    ar_cfg = configparser.ConfigParser()
    ar_cfg.optionxform = str
    try:
        ar_cfg.read(ar_fn)
        ar = AuthenticationRecord.deserialize(json.dumps(dict(ar_cfg["Authentication Record"])))
    except:
        logging.exception("Couldn't load authentication record")
        ar = None

    username = config.get("username", None)

    redirect_uri = f"http://localhost:{config['authentication_callback_port']}"
    cred = InteractiveBrowserCredential(tenant_id=config["tenant_id"],
                                        client_id=config["application_id"],
                                        client_credential=config["application_secret"],
                                        login_hint=username,
                                        redirect_uri=redirect_uri,
                                        cache_persistence_options=TokenCachePersistenceOptions(),
                                        authentication_record=ar)
    ar = cred.authenticate(scopes=["https://graph.microsoft.com/.default"])
    if username not in (None, ar.username):
        raise Exception(f"Bad authenticated user name {ar.username} ({username} expected)!")
    try:
        ar_cfg["Authentication Record"] = json.loads(ar.serialize())
        ar_fn.parent.mkdir(exist_ok=True, parents=True)
        with open(ar_fn, 'w') as f:
            ar_cfg.write(f)
        return cred
    except:
        logging.warn("Unable to save authentication record", exc_info=True)

def daemonize():
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    os.setsid()
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    os.chdir("/")

    sys.stdout.flush()
    sys.stderr.flush()
    si = open(os.devnull, 'r')
    so = open(os.devnull, 'a+')
    se = open(os.devnull, 'a+')
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())
    logging.info(f"msgraphfs sent to background (pid: {os.getpid()})")

def main():
    options = parse_args()
    tenant = options.tenant
    config = load_config(tenant)

    if options.mountpoint is None:
        try:
            options.mountpoint = config["mountpoint"]
        except:
            raise Exception(f"mountpoint argument missing")

    log_fn = None if options.foreground else PRIVATE_DIR / f"logs/{tenant}.log"
    init_logging(log_fn, options.debug)

    cred = authenticate(config)

    graph_fs = GraphFS(tenant,
                       cred.get_token("https://graph.microsoft.com/.default").token)

    fuse_options = set(pyfuse3.default_options)
    fuse_options.add('fsname=msgraphfs')
    if options.debug_fuse:
        fuse_options.add('debug')

    if not options.foreground:
        daemonize()

    try:
        pyfuse3.init(graph_fs, options.mountpoint, fuse_options)
        trio.run(pyfuse3.main)
    except:
        logging.exception("Some unhandled error happened, shutting down file system!")
        pyfuse3.close(unmount=True)
    else:
        logging.info("Unmounting file system and terminating. Have a nice day!")
        pyfuse3.close(unmount=True)

if __name__ == '__main__':
    main()
