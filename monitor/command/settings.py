import os
import io
import json
import time
import uuid
import copy
import utils
import pyotp
import psutil
import socket
import base64
import config
import zipfile
import threading
from  smtp        import EmailSMTP
from  mkcert      import makecerts
from  pathlib     import Path
from  datetime    import datetime
from  contextlib  import contextmanager

xray = Path('/opt/xray')
frps = Path('/opt/frps')
root = Path('/opt/monitor')
rule = Path('/opt/monitor/datas/custom')

xray.mkdir(exist_ok=True, parents=True)
frps.mkdir(exist_ok=True, parents=True)
root.mkdir(exist_ok=True, parents=True)
rule.mkdir(exist_ok=True, parents=True)

class queuelock:
    def __init__(self):
        self.Lock:list = []

    def __gen_id(self):
        return str(time.time()) + utils.secure_code(32)

    def __append(self) -> str:
        _t_id_ = self.__gen_id()
        self.Lock.append(_t_id_)
        return _t_id_

    def __is_top(self, task_id: str) -> bool:
        return self.Lock[0] == task_id

    def __delete(self, task_id: str):
        self.Lock.remove(task_id)

    @contextmanager
    def acquire_lock(self, timeout: float = 0):
        _task_id__ = self.__append()
        start_time = time.time()
        while not self.__is_top(_task_id__):
            if time.time() - start_time > timeout and timeout > 0:
                raise TimeoutError("获取锁超时")
            time.sleep(0.1)
        try:yield
        finally:self.__delete(_task_id__)

    def is_free(self) -> bool:
        return len(self.Lock) == 0

def read_file(name: str) -> str:
    try:
        with open(name, 'rb') as f:
            return f.read().decode()
    except: return ''

def read_file_bytes(name: str) -> bytes:
    try:
        with open(name, 'rb') as f:
            return f.read()
    except: return b''

def write_file(name: str, data: str):
    try:
        with open(name, 'wb') as f:
            f.write(data.encode())
    except: pass

def write_file_bytes(name: str, data: bytes):
    try:
        with open(name, 'wb') as f:
            f.write(data)
    except: pass

def create_zip(files: dict) -> bytes:
    buffer = io.BytesIO()
    
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for filepath, content in files.items():
            zf.writestr(filepath, content)
    
    return buffer.getvalue()

def listdir(path: str, suffix: str = '/'):
    result = []
    
    for entry in os.listdir(path):
        full_path = os.path.join(path, entry)
        
        if os.path.isdir(full_path):
            result.append(entry + suffix)
            for sub_entry in listdir(full_path, suffix):
                result.append(entry + suffix + sub_entry)
        else:   result.append(entry)
    
    return result

def get_server_ip() -> str:
    return socket.gethostbyname(socket.gethostname())

def generate_key() -> tuple:
    pipe = os.popen(str(xray / 'xray') + ' x25519')
    output  = pipe.read()
    private = output.split('\n')[0].split(':')[-1].replace(' ', '')
    public  = output.split('\n')[1].split(':')[-1].replace(' ', '')
    return private, public

def generate_audience() -> str:
    return utils.secure_code(32)

class Settings:
    settings: dict = {}
    makecert: makecerts = None
    smtpsend: EmailSMTP = None
    def __init__(self):
        self.lock = queuelock()
        self.load_settings()
        self.save_settings(True, True)
        threading.Thread(target=self._monitor_thread, daemon=True).start()

    def load_settings(self):
        self.settings = json.loads(read_file(str(root / 'datas/settings.json')))
        self.settings['users'] = self.settings.get('users', {})
        for x in self.settings['users'].values():
            x['keycode'] = x.get('keycode', pyotp.random_base32())
            x['user_id'] = x.get('user_id', self.user_id_generator())
            x['shortid'] = x.get('shortid', self._generate_shortid())
            x['create_time'] = x.get('create_time', 0) or time.time()
            x['secure_code'] = x.get('secure_code', utils.secure_code(2048))
            x['time_offset'] = x.get('time_offset', 8)
            x['custom_data'] = x.get('custom_data', {'direct': [], 'proxy': [], 'reject': []})
            x['description'] = x.get('description', '')
            x['login_require'] = x.get('login_require', 1)
            x['authorization_code'] = x.get('authorization_code', utils.secure_code(2048))
        self.settings['monitor'] = self.settings.get('monitor', {})
        self.settings['monitor']['enable'] = self.settings['monitor'].get('enable', True)
        self.settings['monitor']['cpu_threshold']    = self.settings['monitor'].get('cpu_threshold'   , 80)
        self.settings['monitor']['memory_threshold'] = self.settings['monitor'].get('memory_threshold', 80)
        self.settings['monitor']['check_interval']   = self.settings['monitor'].get('check_interval'  , 60)
        self.settings['monitor']['alert_cooldown']   = self.settings['monitor'].get('alert_cooldown'  , 600)
        self.settings['smtp'] = self.settings.get('smtp', {})
        self.settings['smtp']['email'] = self.settings['smtp'].get('email', '')
        self.settings['smtp']['passcode'] = self.settings['smtp'].get('passcode', '')
        self.settings['auth'] = self.settings.get('auth', {})
        self.settings['auth']['audience'] = self.settings['auth'].get('audience', generate_audience())
        self.settings['auth']['username'] = self.settings['auth'].get('username', 'Custodian')
        self.settings['auth']['password'] = self.settings['auth'].get('password', 'Custodian')
        self.settings['key'] = self.settings.get('key', {})
        if not self.settings['key'].get('private') or not self.settings['key'].get('public'):
            self.settings['key']['private'], self.settings['key']['public'] = generate_key()
        self.settings['serverip'] = self.settings.get('serverip', get_server_ip())
        self.smtpsend = EmailSMTP(**self.settings['smtp'])
        self.makecert = makecerts()
        self.update_frps_certs(False)

    def save_settings(self, restart_xray:bool, restart_frps: bool):
        self.smtpsend.set_email(**self.settings['smtp'])
        with self.lock.acquire_lock():
            write_file(str(root / 'datas/settings.json'), json.dumps(self.settings, indent = 2))
            self._write_config(restart_xray, restart_frps)

    def get_format_time(self, uuid: str, timestamp: float = None, format_set: str = "%Y-%m-%d %H:%M:%S") -> str:
        if timestamp is None: timestamp = time.time()
        return datetime.utcfromtimestamp(timestamp + self.get_time_offset(uuid) * 3600).strftime(format_set)

    def user_id_generator(self) -> str:
        user_id = utils.secure_code_upc(16)
        while  user_id in [ x.get('user_id', '') for x in self.settings.get('users', {}).values() ]:
               user_id = utils.secure_code_upc(16)
        return user_id

    def get_users(self) -> dict[str, dict]:
        def _____(uuid: str, user: dict):
            user['uuid'] = uuid
            del user['keycode']
            del user['secure_code']
            del user['custom_data']
            del user['authorization_code']
            return user
        users = copy.deepcopy( self.settings.get('users', {}) )
        return  {x:_____(x, users[x]) for x in users.keys()}

    def get_user(self, user_uuid: str) -> dict:
        user = copy.deepcopy( self.settings.get('users', {}).get(user_uuid, {}) | {'uuid': user_uuid} )
        del user['keycode']
        del user['secure_code']
        del user['custom_data']
        del user['authorization_code']
        return user

    def get_user_by_email(self, email: str) -> dict:
        for user_uuid, form in self.settings['users'].items():
            if email == form.get('email'):
                form = copy.deepcopy( form | {'uuid': user_uuid} )
                del form['keycode']
                del form['secure_code']
                del form['custom_data']
                del form['authorization_code']
                return form
        return {}

    def get_user_id(self, user_uuid: str) -> str:
        return self.settings.get('users', {}).get(user_uuid, {}).get('user_id', '')

    def get_user_login_require(self, user_uuid: str) -> int:
        return self.settings.get('users', {}).get(user_uuid, {}).get('login_require', 1)

    def get_user_secure_code(self, user_uuid: str) -> str:
        return self.settings.get('users', {}).get(user_uuid, {}).get('secure_code', '')

    def get_user_authorization_code(self, user_uuid: str) -> str:
        return self.settings.get('users', {}).get(user_uuid, {}).get('authorization_code', '')

    def get_user_keycode(self, user_uuid: str) -> str:
        return self.settings.get('users', {}).get(user_uuid, {}).get('keycode', '')

    def get_auth(self) -> dict[str, str]:
        return copy.deepcopy( self.settings.get('auth', {}) )

    def get_user_custom_ruleset(self, user_uuid: str, type: str) -> list:
        if user_uuid not in self.settings.get('users', {}).keys(): return []
        if type not in ['direct', 'proxy', 'reject']: return []
        return self.settings['users'][user_uuid]['custom_data'].get(type, [])

    def get_user_custom_ruleset_filedata(self, user_uuid: str, type: str) -> str:
        ruleset = self.get_user_custom_ruleset(user_uuid, type)
        ruleset_data = 'payload:\n  # user custom ruleset\n' + '\n'.join([f"  - '{rule}'" for rule in ruleset]) + '\n  # default custom ruleset\n'
        ruleset_file = read_file(str(rule / f'{type}.yaml'))
        return ruleset_data + ruleset_file[9:]

    def get_server_ip(self) -> str:
        return self.settings.get('serverip', get_server_ip())

    def check_user_auth(self, email: str, password: str) -> bool:
        for user_uuid, form in self.settings['users'].items():
            if email == form.get('email'):
                return password == form.get('password')
        return  False

    def check_user_secure_code(self, email: str, code: str) -> bool:
        for user_uuid, form in self.settings['users'].items():
            if email == form.get('email'):
                return code == form.get('secure_code')
        return  False

    def check_user_authorization_code(self, client_id: str, client_secret: str) -> bool:
        for user_uuid, form in self.settings['users'].items():
            if client_id and client_id == form.get('user_id'):
                return client_secret and client_secret == form.get('authorization_code')
        return False

    def check_user_TOTP(self, email: str, code: str) -> bool:
        for user_uuid, form in self.settings['users'].items():
            if email == form.get('email'):
                return pyotp.TOTP(form.get('keycode')).verify(code)
        return  False

    def generate_proxy_config(self, user_uuid: str) -> str:
        if user_uuid not in self.settings.get('users', {}).keys(): return
        data = read_file(str(root / 'datas/config.yaml'))
        data = data.replace('#[ca]', '\n      '.join(self.makecert.ca_cert_data.decode().rstrip('\n').split('\n')))
        data = data.replace('#[serverip]' , self.settings.get('serverip', self.get_server_ip()))
        data = data.replace('#[publickey]', self.settings.get('key', {}).get('public', ''))
        data = data.replace('#[shortid]', self.settings.get('users', {}).get(user_uuid, {}).get('shortid', ''))
        data = data.replace('#[uuid]', user_uuid)
        data = data.replace('#[authorization]', 'Basic ' + base64.b64encode('{}:{}'.format(user_uuid, self.settings.get('users', {}).get(user_uuid, {}).get('shortid', '')).encode()).decode())
        return data

    def _write_config(self, restart_xray: bool, restart_frps: bool):
        # frps config
        data = read_file(str(root / 'datas/frps.toml'))
        data = data.replace('#[issuer]'  , self.settings.get('auth', {}).get('issuer'  , f'https://{self.get_server_ip()}:{config.config.get('port', 1000)}'))
        data = data.replace('#[audience]', self.settings.get('auth', {}).get('audience', generate_audience()))
        data = data.replace('#[username]', self.settings.get('auth', {}).get('username', 'Custodian'))
        data = data.replace('#[password]', self.settings.get('auth', {}).get('password', 'Custodian'))
        write_file(frps / 'frps.toml', data)

        # xray config
        data = json.loads(read_file(str(root / 'datas/config.json')))
        for user_uuid, form in self.settings['users'].items():
            user_data = {
                "id": user_uuid,
                "flow": "xtls-rprx-vision",
                "email": form.get('email', ''),
                "level": form.get('xray_level', 2)
            }
            data['inbounds'][0]['settings']['clients'].append(user_data)
            data['inbounds'][0]['streamSettings']['realitySettings']['shortIds'].append(form.get('shortid', self._generate_shortid()))
        data['inbounds'][0]['streamSettings']['realitySettings']['privateKey'] = self.settings.get('key', {}).get('private', '')
        write_file(xray / 'config.json', json.dumps(data, indent = 2))

        # reload xray and restart frps
        if restart_xray: threading.Timer(1.0, lambda: os.system('systemctl restart xray')).start()
        if restart_frps: threading.Timer(1.0, lambda: os.system('systemctl restart frps')).start()

    def _generate_uuid(self) -> str:
        uuid_code = uuid.uuid4()

        while str(uuid_code) in self.settings.get('users', {}).keys():
            uuid_code = uuid.uuid4()

        return str(uuid_code)

    def _generate_shortid(self) -> str:
        shortid = utils.secure_code_hex(16)

        while shortid in [ x.get('shortid', '') for x in self.settings.get('users', {}).values() ]:
            shortid = utils.secure_code_hex(16)

        return shortid

    def create_user(self, email: str, password: str, level: tuple = (1, 2), description: str = ''):
        uuid_code = self._generate_uuid()
        shortid = self._generate_shortid()
        self.settings['users'][uuid_code] = {
            "email": email,
            "shortid": shortid,
            "keycode": pyotp.random_base32(),
            "user_id": self.user_id_generator(),
            "password": password,
            "user_level": level[0],
            "xray_level": level[1],
            "time_offset": 8,
            "create_time": time.time(),
            "secure_code": utils.secure_code(2048),
            "custom_data": {'direct': [], 'proxy': [], 'reject': []},
            "description": description,
            "login_require": 1,
            "authorization_code": utils.secure_code(2048)
        }
        self.save_settings(True, False)

    def delete_user(self, user_uuid: str):
        self.settings['users'].pop(user_uuid, None)
        self.save_settings(True, False)

    def reset_user_id(self, user_uuid: str) -> str:
        if user_uuid not in self.settings.get('users', {}).keys(): return
        uuid_code = self._generate_uuid()
        shortid = self._generate_shortid()
        setting = {}
        for uuid,item in self.settings['users'].items():  # 保持用户列表顺序
            if  uuid == user_uuid:
                setting[uuid_code] = item | {'shortid': shortid}
            else:
                setting[uuid] = item
        self.settings['users']= setting
        self.save_settings(True, False)
        return uuid_code

    def reset_user_email(self, user_uuid: str, email: str):
        if user_uuid not in self.settings.get('users', {}).keys(): return
        self.settings['users'][user_uuid]['email'] = email
        self.save_settings(True, False)

    def reset_user_password(self, user_uuid: str, password: str):
        if user_uuid not in self.settings.get('users', {}).keys(): return
        self.settings['users'][user_uuid]['password'] = password
        self.save_settings(False, False)

    def reset_user_custom_ruleset(self, user_uuid: str, type: str, ruleset: list):
        if user_uuid not in self.settings.get('users', {}).keys(): return
        if type not in ['direct', 'proxy', 'reject']: return
        self.settings['users'][user_uuid]['custom_data'][type] = ruleset
        self.save_settings(False, False)

    def reset_user_description(self, user_uuid: str, description: str):
        if user_uuid not in self.settings.get('users', {}).keys(): return
        self.settings['users'][user_uuid]['description'] = description
        self.save_settings(False, False)

    def reset_user_level(self, user_uuid: str, level: tuple):
        if user_uuid not in self.settings.get('users', {}).keys(): return
        self.settings['users'][user_uuid]['user_level'] = level[0]
        self.settings['users'][user_uuid]['xray_level'] = level[1]
        self.save_settings(True, False)

    def reset_user_login_require(self, user_uuid: str, require: int):
        """
            require:
                1: 仅密码认证
                3: 密码 + 邮箱验证码认证/2FA认证
                5: 密码 + 2FA认证
                7: 密码 + 邮箱验证码认证 + 2FA认证
        """
        if user_uuid not in self.settings.get('users', {}).keys(): return
        self.settings['users'][user_uuid]['login_require'] = require
        self.save_settings(False, False)

    def reset_user_secure_code(self, user_uuid: str) -> str:
        if user_uuid not in self.settings.get('users', {}).keys(): return
        self.settings['users'][user_uuid]['secure_code'] = utils.secure_code(2048)
        self.save_settings(False, False)
        return self.settings['users'][user_uuid]['secure_code']

    def reset_user_authorization_code(self, user_uuid: str) -> str:
        if user_uuid not in self.settings.get('users', {}).keys(): return
        self.settings['users'][user_uuid]['authorization_code'] = utils.secure_code(2048)
        self.save_settings(False, False)
        return self.settings['users'][user_uuid]['authorization_code']

    def reset_user_keycode(self, user_uuid: str) -> str:
        if user_uuid not in self.settings.get('users', {}).keys(): return
        self.settings['users'][user_uuid]['keycode'] = pyotp.random_base32()
        self.save_settings(False, False)
        return self.settings['users'][user_uuid]['keycode']

    def reset_auth(self, username: str, password: str):
        self.settings['auth']['username'] = username
        self.settings['auth']['password'] = password
        self.save_settings(False, True)

    def reset_auth_audience(self):
        self.settings['auth']['audience'] = generate_audience()
        self.save_settings(False, True)

    def reset_smtp_account(self, email: str, passcode: str):
        self.settings['smtp'] = {
            'email': email,
            'passcode': passcode
        }
        self.save_settings(False, False)

    def check_smtp_setting(self) -> bool:
        return self.settings['smtp']['email'] != '' and self.settings['smtp']['passcode'] != ''

    def check_smtp_account(self, email: str) -> bool:
        mhtml = utils.get_index('email/test.html')[0].decode()
        mhtml = mhtml.replace('#[email_id]', utils.request_id_generator())
        mhtml = mhtml.replace('#[time]', self.get_format_time(self.get_user_by_email(email)['uuid']))
        return self.smtpsend.send_email(email,('SMTP 服务配置验证',mhtml),True)

    def send_code_to_email(self, email: str, title: str, code: str, expire: int, ip: str) -> bool:
        mhtml = utils.get_index('email/code.html')[0].decode()
        mhtml = mhtml.replace('#[ip]'   , ip)
        mhtml = mhtml.replace('#[code]' , code)
        mhtml = mhtml.replace('#[time]' , self.get_format_time(self.get_user_by_email(email)['uuid']))
        mhtml = mhtml.replace('#[email]', email)
        mhtml = mhtml.replace('#[expire]'    , str(expire))
        mhtml = mhtml.replace('#[request_id]', utils.request_id_generator())
        return self.smtpsend.send_email(email, (title, mhtml),True)

    def reset_monitor_config(self, config: dict):
        config = {x:config[x] for x in config.keys() if x in ['enable', 'cpu_threshold', 'memory_threshold', 'check_interval', 'alert_cooldown']}
        config['enable']           = config.get('enable', True)
        config['cpu_threshold']    = config.get('cpu_threshold'   , 80)
        config['memory_threshold'] = config.get('memory_threshold', 80)
        config['check_interval']   = config.get('check_interval'  , 60)
        config['alert_cooldown']   = config.get('alert_cooldown'  , 600)
        self.settings['monitor']   = config
        self.save_settings(False, False)

    def update_frps_certs(self, restart_frps: bool = True):
        frps_cert = frps / 'certs'
        frps_cert.mkdir(exist_ok=True, parents=True)
        cert_file = frps_cert / 'server.crt'
        ckey_file = frps_cert / 'server.key'
        
        ckey_bytes, cert_bytes = self.makecert.generate_cert(self.get_server_ip())
        write_file_bytes(cert_file, cert_bytes)
        write_file_bytes(ckey_file, ckey_bytes)
        
        if restart_frps: threading.Timer(1.0, lambda: os.system('systemctl restart frps')).start()

    def get_time_offset(self, uuid: str) -> int:
        if uuid in self.settings['users']:
            return self.settings['users'][uuid].get('time_offset', 8)
        else:
            return 8

    def set_time_offset(self, uuid: str, offset: int):
        if uuid in self.settings['users']:
            self.settings['users'][uuid]['time_offset'] = offset
            self.save_settings(False, False)

    def get_smtp(self):
        return copy.deepcopy( self.settings['smtp'] )

    def get_monitor(self):
        return copy.deepcopy( self.settings['monitor'] )

    def _monitor_thread(self):
        last_alert = 0
        while True:
            try:
                if  self.settings['monitor']['enable'] and \
                    time.time() - last_alert > self.settings['monitor']['alert_cooldown']:
                    cpu_percent = psutil.cpu_percent(interval=1)
                    memory = psutil.virtual_memory()
                    memory_percent = memory.percent
                    cpu_threshold    = self.settings['monitor']['cpu_threshold']
                    memory_threshold = self.settings['monitor']['memory_threshold']
                    cpu_alert    = cpu_percent    > cpu_threshold
                    memory_alert = memory_percent > memory_threshold
                    
                    if  cpu_alert or memory_alert:
                        last_alert = time.time()
                        
                        mhtml = utils.get_index('email/warn.html')[0].decode()
                        mhtml = mhtml.replace('#[cpu_threshold]'   , str(cpu_threshold))
                        mhtml = mhtml.replace('#[memory_threshold]', str(memory_threshold))
                        mhtml = mhtml.replace('#[cpu_percent]'     , f"{cpu_percent:.1f}")
                        mhtml = mhtml.replace('#[memory_percent]'  , f"{memory_percent:.1f}")
                        mhtml = mhtml.replace('#[cpu_class]'   , 'critical' if cpu_percent    >= 90 else ('warning' if cpu_alert    else ''))
                        mhtml = mhtml.replace('#[memory_class]', 'critical' if memory_percent >= 90 else ('warning' if memory_alert else ''))
                    
                        for item in self.get_users().values():
                            if  item['user_level'] == 0:
                                self.smtpsend.send_email(item['email'],('系统资源告警',mhtml.replace('#[time]', self.get_format_time(item['time_offset']))),True)
            finally: time.sleep(self.settings['monitor']['check_interval'])