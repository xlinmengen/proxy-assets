import os
import io
import time
import array
import string
import psutil
import secrets
import zipfile
import inspect
import requests
import threading
from urllib3.util import Retry

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
    'X-Requested-With': 'XMLHttpRequest',
    'Accept-Encoding': 'gzip, deflate, br, zstd',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Connection': 'keep-alive',
    'Sec-Ch-Ua': '"Chromium";v="143", "Google Chrome";v="143", ";Not A Brand";v="99"',
    'Sec-Ch-Ua-Mobile': '?0',
    'Sec-Ch-Ua-Platform': '"Windows"',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Site': 'same-origin',
    'TE': 'Trailers',
    'Accept':  '*/*',
}

def get_session(headers: dict = {}):
    retries = Retry(
        total=5,
        backoff_factor=2,
        status_forcelist=[502, 503, 504],
        raise_on_status =False
    )

    adapter = requests.adapters.HTTPAdapter(
        pool_connections=20,
        pool_maxsize=50,
        max_retries=retries,
        pool_block =False
    )
    
    headers = HEADERS | headers
    session = requests.Session()
    session.headers.update(headers)
    session.mount('http://' , adapter)
    session.mount('https://', adapter)
    
    return session

def Timer(interval: float, function: callable, args = None, kwargs = None):
    thread = threading.Timer(interval, function, args, kwargs)
    thread.daemon = True
    thread.start()

class Debugger:
    def __init__(self, logfile: str = '/root/Debug.log'):
        self.logfile = open(logfile, 'wb')
    
    def log(self, info: str):
        text = f'[{time.strftime("%Y-%m-%d %H:%M:%S")}]> {info}\n'
        self.logfile.write(text.encode());self.logfile.flush()

    class regist:
        def __init__(self, info: str, logfile):
            text = f'[{time.strftime("%Y-%m-%d %H:%M:%S")}]> {info}\n'
            self.logfile = logfile
            self.logfile.write(text.encode());self.logfile.flush()
        
        def log(self, info: str):
            text = f'\t {info}\n'
            self.logfile.write(text.encode());self.logfile.flush()
        
    def dump_module_tree(self, info: str, module, max_depth=0, show_hidden=False, filter_func=None):
        log = self.regist('# 模块树导出 - 开始：' + info, self.logfile).log
        stack = [(module, "", 0, set())]
        try:
            while stack:
                mod, prefix, depth, seen = stack.pop()
                if max_depth > 0 and depth >= max_depth: continue
                if id(mod) in seen: continue
                seen.add(id(mod))
                log(f"{prefix}📦 {mod.__name__}")
                attrs = sorted(dir(mod))
                for name in attrs:
                    if not show_hidden and name.startswith('_'): continue
                    try:attr = getattr(mod, name)
                    except Exception: continue
                    if filter_func and not filter_func(name, attr): continue
                    if inspect.ismodule(attr) and attr.__name__.startswith(mod.__name__):
                        log(f"{prefix}  └─ 📄 {name} ->")
                        stack.append((attr, prefix + "      ", depth + 1, seen))
                    else:
                        typ = type(attr).__name__
                        suffix = " [proto]" if hasattr(attr, 'DESCRIPTOR') else ""
                        log(f"{prefix}  ├─ 📄 {name} ({typ}){suffix}")
        except Exception as Error: self.log(f'# 模块树导出 - 发生错误：{Error}')
        else: self.log(f'# 模块树导出 - 完成：{info}')

    def find_in_module(self, info: str, module, target, search_attr="name", recursive=True, max_depth=0, match_type="exact"):
        log = self.regist('# 模块搜索 - 开始：' + info, self.logfile).log
        targets = [target] if isinstance(target, str) else target
        match_func = (lambda n: n in targets) if match_type == "exact" else \
                     (lambda n: any(p.lower() in n.lower() for p in targets))
        stack = [(module, 0, set())]
        try:
            while stack:
                mod, depth, seen = stack.pop()
                if max_depth > 0 and depth >= max_depth: continue
                if id(mod) in seen: continue
                seen.add(id(mod))
                for name in dir(mod):
                    try:obj = getattr(mod, name)
                    except Exception: continue
                    if search_attr == "name":
                        if match_func(name):
                            log(f"✅ 找到 {name} 在模块: {mod.__name__}")
                    else:
                        if hasattr(obj, search_attr) and match_func(name):
                            log(f"✅ 找到 {name} (具有 {search_attr}) 在模块: {mod.__name__}")
                if recursive:
                    for name in dir(mod):
                        try:obj = getattr(mod, name)
                        except Exception: continue
                        if inspect.ismodule(obj) and obj.__name__.startswith(mod.__name__):
                            stack.append((obj, depth + 1, seen))
        except Exception as Error: self.log(f'# 模块搜索 - 发生错误：{Error}')
        else: self.log(f'# 模块搜索 - 完成：{info}')

class SCode_Generator:
    def __init__(self, charlist: str):
        self.CODESTR = charlist
        self.CODEMAP = array.array('u', [tuple(charlist)[i % len(tuple(charlist))] for i in range(256)])

    def generate(self, length: int):
        if  length <= 4:
            return ''.join(secrets.choice(self.CODESTR) for _ in range(length))
        
        result = array.array('u', ['\0'] * length)
        rand_bytes = secrets.token_bytes(length)
        
        for i in range(length):result[i] = self.CODEMAP[rand_bytes[i]]
        
        return result.tounicode()

secure_code     = SCode_Generator(string.digits + string.ascii_letters).generate
secure_code_hex = SCode_Generator(string.digits + "ABCDEF").generate
secure_code_upc = SCode_Generator(string.digits + string.ascii_uppercase).generate

class Key_Generator:
    def __init__(self, timeout: float = 10 * 60):
        self.key = time.time()
        self.timeout = timeout
        
    def get(self) -> float:
        if  time.time() - self.key > self.timeout:
            self.key = time.time()
        return self.key
        
    def refresh(self):
        self.key = time.time()

class RepeatTimer:
    def __init__(self,  interval, func, *args, **kwargs):
        self.interval = interval
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self._running = False
    
    def _run(self):
        if self._running:
            self.func(*self.args, **self.kwargs)
            self.timer = threading.Timer(self.interval, self._run)
            self.timer.daemon = True
            self.timer.start()
    
    def start(self):
        self._running = True
        self._run()
    
    def stop(self):
        self._running = False
        if hasattr(self, 'timer'):
            self.timer.cancel()

class Tokens:
    def __init__(self, expire: float = 30, length: int = 512):
        self._expire = expire
        self._length = length
        self._tokens = {}
        self._ctimer = RepeatTimer(40.0, self.__cleanup__)
        self._ctimer.start()

    def __cleanup__(self):
        current_time = time.time()
        self._tokens = {k: v for k, v in self._tokens.items() if v['expire'] > current_time}

    def token_gen(self, sign: None) -> str:
        token = secure_code_upc(self._length)
        while self.check(token): token = secure_code_upc(self._length)
        self._tokens[token] = {'sign': sign, 'expire': time.time() + self._expire}
        return token
    
    def check( self, token: str) -> bool:
        self.__cleanup__()
        return self._tokens.get(token, {}).get('expire', 0) > time.time()
    
    def get(self, token: str):
        if  self.check(token):
            return self._tokens.get(token)['sign']

    def pop(self, token: str):
        if  self.check(token):
            return self._tokens.pop(token)['sign']

def get_index(path: str) -> tuple[bytes, int]:
    index_file = os.path.join(os.getcwd(), 'templates', path)
    if os.path.isfile(index_file):
        try:
            with open(index_file, 'rb') as f:
                return f.read(), 200
        except: pass
    return b'', 404

def Last_Modified() -> str:
    return time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())

def get_res_headers(content_length: int, file_name: str) -> dict:
    res_headers = {
        'Last-Modified': Last_Modified(),
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'public, max-age=3600',
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': f'attachment; filename="{file_name}"'
    }
    return res_headers | ({'Content-Length': content_length} if content_length else {})

def request_id_generator() -> str:
    timestamp = format(int(time.time() * 100) % 1000000, '06d')
    return f"{timestamp}-{secure_code_hex(8)}"

def compress_cert(key_bytes:bytes, cert_bytes:bytes) -> bytes:
    buffer = io.BytesIO()
    
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('cert.key', key_bytes)
        zf.writestr('cert.crt', cert_bytes)
    
    return buffer.getvalue()

def get_system_cpu_info(interval: float = 1, percpu: bool = False) -> dict:
    return {
        'times': psutil.cpu_times(),
        'stats': psutil.cpu_stats(),
        'count': psutil.cpu_count(),
        'usage': psutil.cpu_percent(interval=interval, percpu=percpu),
        'frequency': psutil.cpu_freq(),
        'loadaverge': psutil.getloadavg()
    }

def get_system_memory_info() -> dict[str, int|float]:
    """
    获取系统总内存、已用内存和占用百分比
        :return: 
            {
                "total": 总内存(B),
                "used": 已用内存(B),
                "percent": 占用百分比
            }
    """
    try:
        mem = psutil.virtual_memory()
        return {
            "total"  : mem.total,
            "used"   : mem.used,
            "percent": mem.percent
        }
    except: return {
        "total"  : 0,
        "used"   : 0,
        "percent": 0
    }

def cprint(text, color='green', bold=False):
    colors = {
        'black': '\033[30m',
        'red': '\033[31m',
        'green': '\033[32m',
        'yellow': '\033[33m',
        'blue': '\033[34m',
        'magenta': '\033[35m',
        'cyan': '\033[36m',
        'white': '\033[37m',
        'bright_black': '\033[90m',
        'bright_red': '\033[91m',
        'bright_green': '\033[92m',
        'bright_yellow': '\033[93m',
        'bright_blue': '\033[94m',
        'bright_magenta': '\033[95m',
        'bright_cyan': '\033[96m',
        'bright_white': '\033[97m',
    }
    print(f"{colors.get('cyan', '')} | \033[0m{'\033[1m' if bold else ''}{colors.get(color, '')}{text}\033[0m")