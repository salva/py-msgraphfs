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

faulthandler.enable()
UID = os.geteuid()
GID = os.getegid()
BLKSIZE = 65536
graph_url = "https://graph.microsoft.com/v1.0"

# expire data after given seconds
expiration = 30

def bs(s):
    return bytes(s, "utf-8")

def u8(b):
    return b.decode("utf-8")

def date2epoch_ns(txt):
    return dateutil.parser.isoparse(txt).timestamp()*1000000000

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

class NodeAny():
    def __init__(self, id=None, inode=None, **kwargs):
        self.id = id
        st = pyfuse3.EntryAttributes()
        self.st = st
        st.st_ino = inode
        st.generation = 0
        st.entry_timeout = 60
        st.attr_timeout = 60
        st.st_uid = UID
        st.st_gid = GID
        st.st_rdev = 0
        self.refresh(**kwargs)

    def refresh(self, ctime=0, mtime=None, size=0):
        st = self.st
        st.st_size = size
        st.st_ctime_ns = ctime
        st.st_mtime_ns = st.st_ctime_ns if mtime is None else mtime
        st.st_atime_ns = st.st_mtime_ns

    def is_file(self):
        return False

    def is_dir(self):
        return False

    def _to_dict(self):
        r = {**self.__dict__, 'st': attr2dict(self.st)}
        try:
            r["children"] = [u8(c) for c in r["children"].keys()]
        except:
            pass
        return r

    def _to_json(self):
        return json.dumps(self._to_dict())

class NodeDir(NodeAny):
    def __init__(self, children = None, **kwargs):
        super().__init__(**kwargs)
        self.st.st_mode = stat.S_IFDIR | 0o700
        self.children = children

    def is_dir(self):
        return True

    def refresh(self, child_count=0, special_folder=None, **kwargs):
        super().refresh(**kwargs)
        self.child_count = child_count
        self.special_folder = special_folder

class NodeFile(NodeAny):
    def __init__(self, download_url = None, **kwargs):
        super().__init__(**kwargs)
        self.st.st_mode = stat.S_IFREG | 0o600
        self.download_url = download_url

    def is_file(self):
        return True

    def refresh(self, download_url=None, **kwargs):
        super().refresh(**kwargs)
        self.download_url = download_url

class OpenAny():
    def __init__(self, node):
        self.node = node

class OpenFile(OpenAny):
    def __init__(self, node, download_url):
        super().__init__(node)
        self.download_url = download_url
    pass

class OpenDir(OpenAny):
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
        self._init_skeleton()
        self._client = httpx.AsyncClient()

    def _alloc_fileno(self):
        try:
            return self._filenos_available.pop()
        except:
            self._fileno_max += 1
            return self._fileno_max

    def _release_fileno(self, fileno):
        self._filenos_available.append(fileno)

    def _node_by_inode(self, inode):
        try:
            return self._by_inode[inode]
        except:
            raise pyfuse3.FUSEError(errno.ENOENT)

    def _init_skeleton(self):
        me_node = self._alloc_node("d", id=":me")
        root_node = self._alloc_node("d", id=":root",
                                     inode=pyfuse3.ROOT_INODE,
                                     children = { b"me": me_node })

    def _alloc_node(self, type, id, inode=None, **kwargs):
        if inode is None:
            inode = self._alloc_inode()
        klass = NodeDir if type == "d" else NodeFile
        node = klass(id=id, inode=inode, **kwargs)
        self._by_inode[inode] = node
        self._by_id[id] = node
        return node

    def _alloc_or_refresh_node(self, type, id, **kwargs):
        try:
            node = self._by_id[id]
            if type == "f":
                assert node.is_file()
            else:
                assert node.is_dir()
            node.refresh(**kwargs)
            return node
        except:
            return self._alloc_node(type, id, **kwargs)

    def _alloc_or_refresh_node_from_response(self, data):
        type = "f" if "file" in data else "d"
        attrs = {"size": data.get("size", 0) }
        try:
            attrs["ctime"] = date2epoch_ns(data["createdDateTime"])
        except:
            logging.exception("Unable to retrieve createDateTime")
        try:
            attrs["mtime"] = date2epoch_ns(data["lastModifiedDateTime"])
        except:
            logging.exception("Unable to retrieve lastModifiedDateTime")
        if type == "f":
            try:
                attrs["download_url"] = data["@microsoft.graph.downloadUrl"]
            except:
                logging.exception("Unable to retrieve downloadUrl")
        elif type == "d":
            try:
                attrs["child_count"] = data["folder"]["childCount"]
            except:
                logging.exception("Unable to retrieve child count")
            try:
                attrs["special_folder"] = data["specialFolder"]["name"]
            except:
                logging.exception("Unable to retrieve special folder name")

        child = self._alloc_or_refresh_node(type, id=data["id"], **attrs)
        return (bs(data["name"]), child)

    def _alloc_inode(self):
        self._last_inode += 1
        return self._last_inode

    async def lookup(self, parent_inode, name, ctx=None):
        logging.info(f"lookup({parent_inode}, {name})")
        parent_node = self._node_by_inode(parent_inode)
        node = await self._lookup(parent_node, name)
        return await self._getattr(node)

    async def _lookup(self, parent_node, name):
        children = parent_node.children
        if not children or name not in children:
            await self._refresh_dir(parent_node)
        try:
            return parent_node.children[name]
        except:
            raise pyfuse3.FUSEError(errno.ENOENT)

    def _node_url(self, node, path=""):
        id = node.id
        if id.startswith(":"):
            if id == ":me":
                return f"/me/drive/root{path}"
            raise pyfuse3.FUSEError(errno.EACCES)
        return f"/me/drive/items/{id}{path}"

    async def _refresh_dir(self, node):
        try:
            url = self._node_url(node, "/children")
        except: # Static directory, no need to refresh!
            return
        r = await self._get(url)
        try:
            node.children = {}
            for v in r["value"]:
                (name, child) = self._alloc_or_refresh_node_from_response(v)
                node.children[name] = child
                if child.is_dir():
                    logging.info(f"child: [{node.st.st_ino}, {node.id} | {v['name']}] -->\n{json.dumps(v)}\n--\n{child._to_json()}")
        except:
            logging.exception("Exception caught while reloading directory")
            raise pyfuse3.FUSEError(errno.EIO)

    async def getattr(self, inode, ctx=None):
        node = self._node_by_inode(inode)
        st = await self._getattr(node)
        logging.info(f"getattr({inode} [{node.id}]) --> {attr2dict(st)}")
        return st

    async def _getattr(self, node):
        try:
            st = node.st
            # TODO: check expiration
        except:
            await self._fill_attr(node)

        logging.info(f"_getattr({node.id}) --> {attr2dict(node.st)}")
        return node.st

    async def _fill_attr(self, node):
        data = await self._get(self._node_url(node))
        self._alloc_or_refresh_node_from_response(data)

    def _check_dir(self, node):
        if not node.is_dir():
            raise pyfuse3.FUSEError(errno.ENOTDIR)

    def _check_file(self, node):
        if not node.is_file():
            raise pyfuse3.FUSEError(errno.ENOTSUP)

    async def opendir(self, inode, ctx):
        node = self._node_by_inode(inode)
        self._check_dir(node)
        fileno = self._alloc_fileno()
        try:
            e = OpenDir(node)
            await self._refresh_dir(node)
            e.entries = list(node.children.keys())
        except:
            self._filenos_available.append(fileno)
            raise
        self._open_dirs[fileno] = e
        return fileno

    async def readdir(self, fileno, start_id, token):
        e = self._open_dirs[fileno]
        for i in range(start_id, len(e.entries)):
            st = await self._getattr(e.node.children[e.entries[i]])
            ok = pyfuse3.readdir_reply(token, e.entries[i], st, i+1)
            if not ok:
                break

    async def releasedir(self, fileno):
        self._open_dirs.pop(fileno)
        self._filenos_available.append(fileno)

    async def _download_url(self, node):
        try:
            if node.download_url is None:
                url = self._node_url(node, "/content")
                r = await self._get_raw(url)
                if r.status_code == 302:
                    node.download_url = r.headers["Location"]
            return node.download_url
        except:
            raise pyfuse3.FUSEError(errno.ENOENT)

    async def open(self, inode, flags, ctx):
        node = self._node_by_inode(inode)
        self._check_file(node)
        fileno = self._alloc_fileno()
        try:
            url = await self._download_url(node)
            e = OpenFile(node, download_url = url)
        except:
            self._filenos_available.append(fileno)
            raise
        self._open_files[fileno] = e
        return pyfuse3.FileInfo(fh=fileno, direct_io=False, keep_cache=False)

    async def read(self, fileno, offset, size):
        e = self._open_files[fileno]
        r = await self._get_raw(e.download_url, headers={"Range": f"bytes={offset}-{offset+size-1}"})
        logging.info(f"read({fileno}, offset={offset}, size={size}) --> {len(r.content)} bytes")
        return r.content

    async def flush(self, fileno):
        pass

    async def release(self, fileno):
        self._open_files.pop(fileno)
        self._filenos_available.append(fileno)

    async def mkdir(self, parent_inode, name, mode, ctx):
        parent_node = self._node_by_inode(parent_inode)
        url = self._node_url(parent_node, "/children")
        r = await self._post_raw(url, data = { "name": u8(name),
                                               "folder": {},
                                               "@microsoft.graph.conflictBehavior": "fail" })
        if r.status_code == 201: # Created!
            (name, node) = self._alloc_or_refresh_node_from_response(parent_node, r.json())
            if node.children is not None:
                node.children[name] = node
            return node.st
        if r.status_code == 409: # Conflict!
            raise pyfuse3.FUSEError(errno.EEXIST)
        logging.error(f"Unexpected response for mkdir: code: {r.status_code}")
        raise pyfuse3.FUSEError(errno.EIO) # Unhandled response

    async def rmdir(self, parent_inode, name, ctx):
        parent_node = self._node_by_inode(parent_inode)
        node = await self._lookup(parent_node, name)
        if not node.is_dir():
            raise pyfuse3.FUSEError(errno.ENOTDIR)
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
        parent_node = self._node_by_inode(parent_inode)
        node = await self._lookup(parent_node, name)
        if not node.is_file():
            raise pyfuse3.FUSEError(errno.EACCES)
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
        parent_node_old = self._node_by_inode(parent_inode_old)
        node = await self._lookup(parent_node_old, name_old)
        parent_node_new = self._node_by_inode(parent_inode_new)

        url = self._node_url(node)
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
        return r.json()

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
        logging.info(f"POST {url} --> status code: {r.status_code}, content:\n{u8(r.content)}")
        return r

    def _post_raw(self, url, **kwargs): # Implicit async!
        return self._send_raw(self._client.post, url, **kwargs)

    def _patch_raw(self, url, **kwargs): # Implicit async!
        return self._send_raw(self._client.patch, url, **kwargs)

    async def _delete_raw(self, url, headers={}, **kwargs):
        headers = { "Authorization": f"Bearer {self._graph_token}", **headers }
        url = self._mkurl(url)
        r = await self._client.delete(url, headers=headers, **kwargs)
        logging.info(f"DELETE {url} --> status code: {r.status_code}, content:\n{u8(r.content)}")
        return r

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
