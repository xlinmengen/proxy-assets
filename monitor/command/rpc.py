# -*- coding: utf-8 -*-
"""
RPC Library with TCP/UDP support, auto protocol selection, and optional authentication.

Features:
- Transparent remote object proxy (supports attributes, methods, containers, operators).
- Protocol: TCP, UDP, or mix (auto-switch based on payload size).
- Auto mode: uses mix for loopback, TCP otherwise.
- TCP keepalive (off by default, non-thread-safe).
- UDP fragmentation with request_id (supports large messages).
- Asynchronous UDP request processing via thread pool.
- Optional username/password authentication (disabled by default).
- Warning: Pickle serialization is not safe for untrusted networks.
"""

import socket
import pickle
import logging
import threading
import struct
import time
import random
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

# ---------- Serialization ----------
def _serialize(obj):
    return pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)

def _deserialize(data):
    return pickle.loads(data)

# ---------- UDP fragmentation protocol (with request_id) ----------
UDP_CHUNK_SIZE = 60000
# Header: total_chunks(2B), chunk_idx(2B), total_len(4B), request_id(4B)
UDP_HEADER_FMT = struct.Struct('!HHII')
UDP_HEADER_SIZE = UDP_HEADER_FMT.size

def _is_loopback(host):
    if host in ('localhost', '127.0.0.1', '::1'):
        return True
    try:
        ip = socket.gethostbyname(host)
        return ip in ('127.0.0.1', '::1')
    except socket.gaierror:
        return False

# ===================== Remote proxies =====================
class _RemoteMethod:
    __slots__ = ('_client', '_obj_name', '_path')
    def __init__(self, client, obj_name, path):
        self._client = client
        self._obj_name = obj_name
        self._path = path
    def __call__(self, *args, **kwargs):
        return self._client._send_command({
            'type': 'call',
            'obj_name': self._obj_name,
            'path': self._path,
            'args': args,
            'kwargs': kwargs
        })

class _RemoteProxy:
    __slots__ = ('_client', '_obj_name', '_path')
    def __init__(self, client, obj_name=None, path=None):
        self._client = client
        self._obj_name = obj_name
        self._path = path or []
    def _send(self, cmd):
        if 'obj_name' not in cmd:
            cmd['obj_name'] = self._obj_name
        return self._client._send_command(cmd)
    # ----- All magic methods (unchanged) -----
    def __getattribute__(self, name):
        if name.startswith('_') and name not in ('_client', '_obj_name', '_path'):
            return object.__getattribute__(self, name)
        client = object.__getattribute__(self, '_client')
        obj_name = object.__getattribute__(self, '_obj_name')
        path = object.__getattribute__(self, '_path') + [name]
        resp = client._send_command({
            'type': 'inspect',
            'obj_name': obj_name,
            'path': path
        })
        if resp['type'] == 'value':
            return resp['data']
        elif resp['type'] == 'callable':
            return _RemoteMethod(client, obj_name, path)
        else:
            return _RemoteProxy(client, obj_name, path)
    def __setattr__(self, name, value):
        if name in ('_client', '_obj_name', '_path'):
            object.__setattr__(self, name, value)
        else:
            path = object.__getattribute__(self, '_path') + [name]
            self._send({'type': 'setattr', 'path': path, 'value': value})
    def __delattr__(self, name):
        path = object.__getattribute__(self, '_path') + [name]
        self._send({'type': 'delattr', 'path': path})
    def __getitem__(self, key):
        return self._send({'type': 'getitem', 'path': self._path, 'key': key})
    def __setitem__(self, key, value):
        self._send({'type': 'setitem', 'path': self._path, 'key': key, 'value': value})
    def __delitem__(self, key):
        self._send({'type': 'delitem', 'path': self._path, 'key': key})
    def __len__(self):
        return self._send({'type': 'len', 'path': self._path})
    def __iter__(self):
        items = self._send({'type': 'iter', 'path': self._path})
        return iter(items)
    def __contains__(self, item):
        return self._send({'type': 'contains', 'path': self._path, 'item': item})
    def __enter__(self):
        return self._send({'type': 'enter', 'path': self._path})
    def __exit__(self, exc_type, exc_val, exc_tb):
        self._send({'type': 'exit', 'path': self._path, 'args': (exc_type, exc_val, exc_tb)})
    def __eq__(self, other):
        return self._send({'type': 'eq', 'path': self._path, 'other': other})
    def __ne__(self, other):
        return self._send({'type': 'ne', 'path': self._path, 'other': other})
    def __lt__(self, other):
        return self._send({'type': 'lt', 'path': self._path, 'other': other})
    def __le__(self, other):
        return self._send({'type': 'le', 'path': self._path, 'other': other})
    def __gt__(self, other):
        return self._send({'type': 'gt', 'path': self._path, 'other': other})
    def __ge__(self, other):
        return self._send({'type': 'ge', 'path': self._path, 'other': other})
    def __add__(self, other):
        return self._send({'type': 'add', 'path': self._path, 'other': other})
    def __sub__(self, other):
        return self._send({'type': 'sub', 'path': self._path, 'other': other})
    def __mul__(self, other):
        return self._send({'type': 'mul', 'path': self._path, 'other': other})
    def __truediv__(self, other):
        return self._send({'type': 'truediv', 'path': self._path, 'other': other})
    def __floordiv__(self, other):
        return self._send({'type': 'floordiv', 'path': self._path, 'other': other})
    def __mod__(self, other):
        return self._send({'type': 'mod', 'path': self._path, 'other': other})
    def __pow__(self, other):
        return self._send({'type': 'pow', 'path': self._path, 'other': other})
    def __and__(self, other):
        return self._send({'type': 'and', 'path': self._path, 'other': other})
    def __or__(self, other):
        return self._send({'type': 'or', 'path': self._path, 'other': other})
    def __xor__(self, other):
        return self._send({'type': 'xor', 'path': self._path, 'other': other})
    def __lshift__(self, other):
        return self._send({'type': 'lshift', 'path': self._path, 'other': other})
    def __rshift__(self, other):
        return self._send({'type': 'rshift', 'path': self._path, 'other': other})
    def __radd__(self, other):
        return self._send({'type': 'radd', 'path': self._path, 'other': other})
    def __rsub__(self, other):
        return self._send({'type': 'rsub', 'path': self._path, 'other': other})
    def __neg__(self):
        return self._send({'type': 'neg', 'path': self._path})
    def __pos__(self):
        return self._send({'type': 'pos', 'path': self._path})
    def __abs__(self):
        return self._send({'type': 'abs', 'path': self._path})
    def __invert__(self):
        return self._send({'type': 'invert', 'path': self._path})
    def __str__(self):
        return self._send({'type': 'str', 'path': self._path})
    def __repr__(self):
        return self._send({'type': 'repr', 'path': self._path})
    def __int__(self):
        return self._send({'type': 'int', 'path': self._path})
    def __float__(self):
        return self._send({'type': 'float', 'path': self._path})
    def __bool__(self):
        return self._send({'type': 'bool', 'path': self._path})
    def __hash__(self):
        return self._send({'type': 'hash', 'path': self._path})
    def __call__(self, *args, **kwargs):
        return self._send({'type': 'call', 'path': self._path, 'args': args, 'kwargs': kwargs})
    def __dir__(self):
        return self._send({'type': 'dir', 'path': self._path})

# ===================== RPC Client =====================
class RPCClient:
    def __init__(self, host='127.0.0.1', port=8888, protocol='auto',
                 threshold=1400, timeout=5.0, tcp_keepalive=False,
                 auth=None):
        """
        :param host: server address
        :param port: port (shared by TCP and UDP)
        :param protocol: 'tcp', 'udp', 'mix', 'auto'
        :param threshold: mix mode UDP->TCP switch threshold (bytes)
        :param timeout: UDP timeout (seconds)
        :param tcp_keepalive: reuse TCP connection (non-thread-safe!)
        :param auth: dict with 'username' and 'password' for authentication,
                     or None (default) to disable authentication.
                     Enabling auth adds overhead on every request.
        """
        self._host = host
        self._port = port
        self._timeout = timeout
        self._threshold = threshold
        self._tcp_keepalive = tcp_keepalive
        self._auth = auth  # None or dict

        if protocol == 'auto':
            self._effective = 'mix' if _is_loopback(host) else 'tcp'
        elif protocol in ('tcp', 'udp', 'mix'):
            self._effective = protocol
        else:
            raise ValueError("protocol must be 'tcp', 'udp', 'mix', or 'auto'")

        self._tcp_sock = None
        self._tcp_lock = threading.Lock()

    def _send_command(self, cmd):
        # Inject authentication if enabled
        if self._auth is not None:
            cmd['_auth'] = self._auth.copy()  # avoid modifying original

        data = _serialize(cmd)
        if self._effective == 'tcp':
            return self._send_tcp(data)
        elif self._effective == 'udp':
            return self._send_udp(data)
        elif self._effective == 'mix':
            if len(data) <= self._threshold:
                return self._send_udp(data)
            else:
                return self._send_tcp(data)
        else:
            raise RuntimeError(f"Invalid effective protocol: {self._effective}")

    # ---------- TCP transport ----------
    def _send_tcp(self, data):
        if self._tcp_keepalive:
            return self._send_tcp_keepalive(data)
        else:
            return self._send_tcp_once(data)

    def _send_tcp_once(self, data):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self._host, self._port))
            s.sendall(len(data).to_bytes(4, 'big') + data)
            len_data = s.recv(4)
            if not len_data:
                raise ConnectionError("Server closed connection")
            resp_len = int.from_bytes(len_data, 'big')
            resp_data = b''
            while len(resp_data) < resp_len:
                chunk = s.recv(resp_len - len(resp_data))
                if not chunk:
                    break
                resp_data += chunk
            resp = _deserialize(resp_data)
            if resp.get('error'):
                raise Exception(resp['error'])
            return resp['result']

    def _send_tcp_keepalive(self, data):
        with self._tcp_lock:
            for attempt in range(2):
                try:
                    if self._tcp_sock is None:
                        self._tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        self._tcp_sock.connect((self._host, self._port))
                    self._tcp_sock.sendall(len(data).to_bytes(4, 'big') + data)
                    len_data = self._tcp_sock.recv(4)
                    if not len_data:
                        raise ConnectionError("Server closed connection")
                    resp_len = int.from_bytes(len_data, 'big')
                    resp_data = b''
                    while len(resp_data) < resp_len:
                        chunk = self._tcp_sock.recv(resp_len - len(resp_data))
                        if not chunk:
                            break
                        resp_data += chunk
                    resp = _deserialize(resp_data)
                    if resp.get('error'):
                        raise Exception(resp['error'])
                    return resp['result']
                except (BrokenPipeError, ConnectionResetError, OSError) as e:
                    if self._tcp_sock:
                        try:
                            self._tcp_sock.close()
                        except:
                            pass
                        self._tcp_sock = None
                    if attempt == 0:
                        continue
                    else:
                        raise ConnectionError(f"TCP keepalive failed: {e}")
            raise ConnectionError("TCP keepalive failed after retry")

    # ---------- UDP transport ----------
    def _send_udp(self, data):
        request_id = random.getrandbits(32)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(self._timeout)
            s.connect((self._host, self._port))
            self._udp_send_chunked(s, data, request_id)
            resp_data = self._udp_recv_chunked(s)
            if not resp_data:
                raise ConnectionError("Empty UDP response")
            resp = _deserialize(resp_data)
            if resp.get('error'):
                raise Exception(resp['error'])
            return resp['result']

    def _udp_send_chunked(self, sock, data, request_id):
        total = (len(data) + UDP_CHUNK_SIZE - 1) // UDP_CHUNK_SIZE
        header = UDP_HEADER_FMT.pack(total, 0, len(data), request_id)
        if total == 1:
            sock.sendall(header + data)
        else:
            for idx in range(total):
                start = idx * UDP_CHUNK_SIZE
                chunk = data[start:start + UDP_CHUNK_SIZE]
                hdr = UDP_HEADER_FMT.pack(total, idx, len(data), request_id)
                sock.sendall(hdr + chunk)

    def _udp_recv_chunked(self, sock):
        first = sock.recv(65507)
        if len(first) < UDP_HEADER_SIZE:
            # fallback to legacy format (no header)
            return first
        total, idx, total_len, request_id = UDP_HEADER_FMT.unpack(first[:UDP_HEADER_SIZE])
        payload = first[UDP_HEADER_SIZE:]
        if total == 1:
            return payload
        chunks = {idx: payload}
        while len(chunks) < total:
            chunk_data = sock.recv(65507)
            t, i, _, _ = UDP_HEADER_FMT.unpack(chunk_data[:UDP_HEADER_SIZE])
            chunks[i] = chunk_data[UDP_HEADER_SIZE:]
        merged = b''.join(chunks[i] for i in range(total))
        return merged[:total_len]

    # ---------- Proxy entry ----------
    def __getattr__(self, name):
        return _RemoteProxy(self, obj_name=name)

    def __setattr__(self, name, value):
        if name.startswith('_'):
            object.__setattr__(self, name, value)
        else:
            raise AttributeError(f"Cannot set attribute '{name}' on RPCClient")

    def get_proxy(self, name):
        return _RemoteProxy(self, obj_name=name)

    def close(self):
        if self._tcp_sock:
            try:
                self._tcp_sock.close()
            except:
                pass
            self._tcp_sock = None

# ===================== RPC Server =====================
class RPCServer:
    def __init__(self, host='127.0.0.1', port=8888, max_workers=None, auth=None):
        """
        :param host: bind address
        :param port: bind port (both TCP and UDP)
        :param max_workers: thread pool size for UDP processing
        :param auth: dict with 'username' and 'password' for authentication,
                     or None (default) to disable.
                     Enabling auth adds overhead on every request.
        """
        self.objects = {}
        self.host = host
        self.port = port
        self.serve_activity = True
        self._auth = auth   # None or dict

        self._tcp_sock = None
        self._udp_sock = None
        self._pending = {}
        self._pending_lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=max_workers)

    def register(self, name, obj):
        if name in self.objects:
            raise ValueError(f"Object '{name}' already registered")
        self.objects[name] = obj

    def __setattr__(self, name, value):
        reserved = ('objects', 'host', 'port', 'serve_activity',
                    '_tcp_sock', '_udp_sock', '_pending', '_pending_lock',
                    '_executor', '_auth')
        if name.startswith('_') or name in reserved:
            object.__setattr__(self, name, value)
        else:
            self.register(name, value)

    def _get_by_path(self, obj_name, path):
        if not obj_name:
            raise ValueError("Object name must be specified")
        obj = self.objects.get(obj_name)
        if obj is None:
            raise KeyError(f"Object '{obj_name}' not registered")
        for attr in path:
            obj = getattr(obj, attr)
        return obj

    # ---------- Command processing core (with authentication) ----------
    def _process_command(self, cmd):
        # ---------- AUTHENTICATION CHECK ----------
        if self._auth is not None:
            client_auth = cmd.get('_auth')
            if client_auth != self._auth:
                raise PermissionError("Authentication failed: invalid credentials")
        # --------------------------------------------

        typ = cmd.get('type')
        obj_name = cmd.get('obj_name')
        path = cmd.get('path', [])
        try:
            if typ == 'inspect':
                obj = self._get_by_path(obj_name, path)
                if callable(obj):
                    result = {'type': 'callable', 'data': None}
                elif isinstance(obj, (int, float, str, bool, type(None), bytes, bytearray)):
                    result = {'type': 'value', 'data': obj}
                else:
                    result = {'type': 'object', 'data': None}
                error = None
            elif typ == 'resolve':
                obj = self._get_by_path(obj_name, path)
                result = obj
                error = None
            elif typ == 'getattr':
                obj = self._get_by_path(obj_name, path)
                result = obj
                error = None
            elif typ == 'setattr':
                obj = self._get_by_path(obj_name, path[:-1])
                setattr(obj, path[-1], cmd['value'])
                result = True
                error = None
            elif typ == 'delattr':
                obj = self._get_by_path(obj_name, path[:-1])
                delattr(obj, path[-1])
                result = True
                error = None
            elif typ == 'call':
                obj = self._get_by_path(obj_name, path)
                result = obj(*cmd.get('args', ()), **cmd.get('kwargs', {}))
                error = None
            elif typ == 'getitem':
                obj = self._get_by_path(obj_name, path)
                result = obj[cmd['key']]
                error = None
            elif typ == 'setitem':
                obj = self._get_by_path(obj_name, path)
                obj[cmd['key']] = cmd['value']
                result = True
                error = None
            elif typ == 'delitem':
                obj = self._get_by_path(obj_name, path)
                del obj[cmd['key']]
                result = True
                error = None
            elif typ == 'len':
                obj = self._get_by_path(obj_name, path)
                result = len(obj)
                error = None
            elif typ == 'iter':
                obj = self._get_by_path(obj_name, path)
                result = list(obj)
                error = None
            elif typ == 'contains':
                obj = self._get_by_path(obj_name, path)
                result = cmd['item'] in obj
                error = None
            elif typ == 'enter':
                obj = self._get_by_path(obj_name, path)
                result = obj.__enter__()
                error = None
            elif typ == 'exit':
                obj = self._get_by_path(obj_name, path)
                result = obj.__exit__(*cmd['args'])
                error = None
            # Comparison operators
            elif typ == 'eq':
                obj = self._get_by_path(obj_name, path)
                result = obj == cmd['other']
                error = None
            elif typ == 'ne':
                obj = self._get_by_path(obj_name, path)
                result = obj != cmd['other']
                error = None
            elif typ == 'lt':
                obj = self._get_by_path(obj_name, path)
                result = obj < cmd['other']
                error = None
            elif typ == 'le':
                obj = self._get_by_path(obj_name, path)
                result = obj <= cmd['other']
                error = None
            elif typ == 'gt':
                obj = self._get_by_path(obj_name, path)
                result = obj > cmd['other']
                error = None
            elif typ == 'ge':
                obj = self._get_by_path(obj_name, path)
                result = obj >= cmd['other']
                error = None
            # Arithmetic operators
            elif typ == 'add':
                obj = self._get_by_path(obj_name, path)
                result = obj + cmd['other']
                error = None
            elif typ == 'sub':
                obj = self._get_by_path(obj_name, path)
                result = obj - cmd['other']
                error = None
            elif typ == 'mul':
                obj = self._get_by_path(obj_name, path)
                result = obj * cmd['other']
                error = None
            elif typ == 'truediv':
                obj = self._get_by_path(obj_name, path)
                result = obj / cmd['other']
                error = None
            elif typ == 'floordiv':
                obj = self._get_by_path(obj_name, path)
                result = obj // cmd['other']
                error = None
            elif typ == 'mod':
                obj = self._get_by_path(obj_name, path)
                result = obj % cmd['other']
                error = None
            elif typ == 'pow':
                obj = self._get_by_path(obj_name, path)
                result = obj ** cmd['other']
                error = None
            elif typ == 'and':
                obj = self._get_by_path(obj_name, path)
                result = obj & cmd['other']
                error = None
            elif typ == 'or':
                obj = self._get_by_path(obj_name, path)
                result = obj | cmd['other']
                error = None
            elif typ == 'xor':
                obj = self._get_by_path(obj_name, path)
                result = obj ^ cmd['other']
                error = None
            elif typ == 'lshift':
                obj = self._get_by_path(obj_name, path)
                result = obj << cmd['other']
                error = None
            elif typ == 'rshift':
                obj = self._get_by_path(obj_name, path)
                result = obj >> cmd['other']
                error = None
            elif typ == 'radd':
                obj = self._get_by_path(obj_name, path)
                result = cmd['other'] + obj
                error = None
            elif typ == 'rsub':
                obj = self._get_by_path(obj_name, path)
                result = cmd['other'] - obj
                error = None
            elif typ == 'neg':
                obj = self._get_by_path(obj_name, path)
                result = -obj
                error = None
            elif typ == 'pos':
                obj = self._get_by_path(obj_name, path)
                result = +obj
                error = None
            elif typ == 'abs':
                obj = self._get_by_path(obj_name, path)
                result = abs(obj)
                error = None
            elif typ == 'invert':
                obj = self._get_by_path(obj_name, path)
                result = ~obj
                error = None
            elif typ == 'str':
                obj = self._get_by_path(obj_name, path)
                result = str(obj)
                error = None
            elif typ == 'repr':
                obj = self._get_by_path(obj_name, path)
                result = repr(obj)
                error = None
            elif typ == 'int':
                obj = self._get_by_path(obj_name, path)
                result = int(obj)
                error = None
            elif typ == 'float':
                obj = self._get_by_path(obj_name, path)
                result = float(obj)
                error = None
            elif typ == 'bool':
                obj = self._get_by_path(obj_name, path)
                result = bool(obj)
                error = None
            elif typ == 'hash':
                obj = self._get_by_path(obj_name, path)
                result = hash(obj)
                error = None
            elif typ == 'dir':
                obj = self._get_by_path(obj_name, path)
                result = dir(obj)
                error = None
            else:
                raise ValueError(f"Unknown command type: {typ}")
        except Exception as e:
            result = None
            error = f"{type(e).__name__}: {e}"
        return {'result': result, 'error': error}

    # ---------- TCP handler ----------
    def _handle_tcp(self, conn):
        try:
            while True:
                len_data = conn.recv(4)
                if not len_data:
                    break
                msg_len = int.from_bytes(len_data, 'big')
                data = b''
                while len(data) < msg_len:
                    chunk = conn.recv(msg_len - len(data))
                    if not chunk:
                        break
                    data += chunk
                if not data:
                    break
                cmd = _deserialize(data)
                resp = self._process_command(cmd)
                resp_data = _serialize(resp)
                conn.sendall(len(resp_data).to_bytes(4, 'big') + resp_data)
        except Exception as e:
            logger.error(f"TCP handler error: {e}")
        finally:
            conn.close()

    # ---------- UDP handler (with thread pool) ----------
    def _handle_udp(self):
        while self.serve_activity:
            try:
                data, addr = self._udp_sock.recvfrom(65507)
                if not data:
                    continue

                if len(data) >= UDP_HEADER_SIZE:
                    total, idx, total_len, request_id = UDP_HEADER_FMT.unpack(data[:UDP_HEADER_SIZE])
                    payload = data[UDP_HEADER_SIZE:]

                    if total > 1:
                        key = (addr, request_id)
                        with self._pending_lock:
                            if key not in self._pending:
                                self._pending[key] = {
                                    'total': total,
                                    'total_len': total_len,
                                    'chunks': {},
                                    'last_active': time.time()
                                }
                            pending = self._pending[key]
                            pending['chunks'][idx] = payload
                            pending['last_active'] = time.time()
                            if len(pending['chunks']) == total:
                                full_data = b''.join(pending['chunks'][i] for i in range(total))
                                full_data = full_data[:total_len]
                                del self._pending[key]
                                self._executor.submit(self._process_udp_request, full_data, addr, request_id)
                            continue
                    else:
                        # single fragment
                        self._executor.submit(self._process_udp_request, payload, addr, request_id)
                        continue

                # legacy format (no header)
                self._executor.submit(self._process_udp_request, data, addr, None)

            except socket.timeout:
                self._cleanup_stale_pending()
                continue
            except Exception as e:
                logger.error(f"UDP receive error: {e}")

    def _process_udp_request(self, raw_data, addr, request_id):
        try:
            cmd = _deserialize(raw_data)
            resp = self._process_command(cmd)
            resp_data = _serialize(resp)
            self._udp_send_chunked_to(resp_data, addr, request_id if request_id is not None else 0)
        except Exception as e:
            logger.error(f"UDP request processing error: {e}")
            error_resp = {'result': None, 'error': f"Processing error: {e}"}
            resp_data = _serialize(error_resp)
            self._udp_send_chunked_to(resp_data, addr, request_id if request_id is not None else 0)

    def _udp_send_chunked_to(self, data, addr, request_id):
        total = (len(data) + UDP_CHUNK_SIZE - 1) // UDP_CHUNK_SIZE
        if total == 1:
            header = UDP_HEADER_FMT.pack(1, 0, len(data), request_id)
            self._udp_sock.sendto(header + data, addr)
        else:
            for idx in range(total):
                start = idx * UDP_CHUNK_SIZE
                chunk = data[start:start + UDP_CHUNK_SIZE]
                header = UDP_HEADER_FMT.pack(total, idx, len(data), request_id)
                self._udp_sock.sendto(header + chunk, addr)

    def _cleanup_stale_pending(self, timeout=10):
        now = time.time()
        with self._pending_lock:
            stale = [key for key, info in self._pending.items()
                     if now - info['last_active'] > timeout]
            for key in stale:
                del self._pending[key]
                logger.warning(f"Cleaned stale UDP fragments for {key}")

    # ---------- Server control ----------
    def serve_forever(self):
        self._tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp_sock.bind((self.host, self.port))
        self._tcp_sock.listen(5)

        self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp_sock.bind((self.host, self.port))
        self._udp_sock.settimeout(1.0)

        threading.Thread(target=self._accept_tcp, daemon=True).start()
        threading.Thread(target=self._handle_udp, daemon=True).start()

        logger.info(f"RPC Server started on {self.host}:{self.port} (TCP+UDP)")
        while self.serve_activity:
            time.sleep(0.1)

        self._tcp_sock.close()
        self._udp_sock.close()
        self._executor.shutdown(wait=False)

    def _accept_tcp(self):
        while self.serve_activity:
            try:
                conn, _ = self._tcp_sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle_tcp, args=(conn,), daemon=True).start()

    def shutdown(self):
        self.serve_activity = False
        if self._tcp_sock:
            try:
                self._tcp_sock.close()
            except:
                pass
        if self._udp_sock:
            try:
                self._udp_sock.close()
            except:
                pass
        self._executor.shutdown(wait=False)