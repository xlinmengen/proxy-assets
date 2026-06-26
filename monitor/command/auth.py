import time, utils, rpc, config, captcha
from flask import session, request, redirect, url_for, jsonify
from functools import wraps
from datetime  import timedelta
from typing    import Optional

def get_client_ip():
    """获取真实客户端 IP"""
    return request.remote_addr

class Auth:
    """基于 session 的认证管理类"""
    def __init__(self, app=None):
        self.client = rpc.RPCClient(**config.rpc_config)
        self.settings = self.client.get_proxy('settings')
        self.login_view = '/'
        self.email_code = utils.Tokens(expire = config.expire, length = 5) # code account
        self.graph_code = utils.Tokens(expire = config.expire, length = 8) # token code
        if app: self.init_app(app)
    
    def init_app(self, app):
        """初始化 Flask 应用"""
        app.config.setdefault('SESSION_PERMANENT', True)
        app.config.setdefault('PERMANENT_SESSION_LIFETIME', timedelta(days=7))
    
    # ========== 验证函数 ==========

    def code_checkup(self, target) -> bool:
        return (session.get('authenticated', 0) & target) == target

    def authenticate(self, username: str, password: str) -> bool:
        """验证用户名密码"""
        return self.settings.check_user_auth(username, password)
    
    def s_authenticate(self, username: str, code: str) -> bool:
        return self.settings.check_user_secure_code(username, code)
    
    def a_authenticate(self, client_id: str, client_secret: str) -> bool:
        return self.settings.check_user_authorization_code(client_id, client_secret)

    def is_authenticated(self) -> bool:
        """检查是否已登录"""
        return session.get('authenticated', 0) >= session.get('userinfo', {}).get('login_require', 1)
    
    def is_high_permission(self) -> bool:
        return session.get('userinfo', {}).get('user_level', 1) == 0

    # ========== 登录/退出 ==========
    
    def login(self, username: str, password: str, verify: Optional[dict] = None, remember: Optional[bool] = None) -> tuple:
        """执行登录"""
        if not username or not password:
            return jsonify({
                'status': False,
                'message': '用户名和密码不能为空',
                'code': 400,
                'info': None
            }), 400
        if type(remember) == bool: session.permanent = remember

        if (not session.get('authenticated') or session.get('username') != username) and self.s_authenticate(username, password):
            session['authenticated'] = 8
            session['username'] = username
            session['login_time'] = time.time()
            session['session_id'] = str(time.time()) + utils.secure_code(32)
            session['userinfo'] = self.settings.get_user_by_email(username)
            session['userinfo']['keycode']     = None
            session['userinfo']['custom_data'] = None
            session['userinfo']['secure_code'] = None

        if (not session.get('authenticated') or session.get('username') != username) and self.authenticate(username, password):
            session['authenticated'] = 1
            session['username'] = username
            session['login_time'] = time.time()
            session['session_id'] = str(time.time()) + utils.secure_code(32)
            session['userinfo'] = self.settings.get_user_by_email(username)
            session['userinfo']['keycode']     = None
            session['userinfo']['custom_data'] = None
            session['userinfo']['secure_code'] = None
        
        if session.get('username') == username and self.s_authenticate(username, password):
            if not self.is_authenticated(): session['authenticated'] += 8
            
            return jsonify({
                'status': True,
                'message': '安全码认证成功',
                'code': 200,
                'info': {'username': username},
                'verify': {
                    'current': session['authenticated'],
                    'require': session['userinfo'].get('login_require', 1)
                },  'authenticated': self.is_authenticated()
            }), 200

        if session.get('username') == username and self.authenticate(username, password):
            if verify and not self.is_authenticated():
                verify_vtype = verify.get('vtype')
                verify_value = verify.get('value')
                if verify_vtype == 'graph':
                    if not type(verify_value) == dict:
                        code  = utils.secure_code(5)
                        token = self.graph_code.token_gen(code)
                        graph = captcha.generator(code, bg_color=(40, 44, 52))
                        return jsonify({
                            'status': True,
                            'message': 'Graph Code Generator',
                            'code': 200,
                            'info': {
                                'username': username,
                                'token': token,
                                'graph': graph
                            },
                            'verify': {
                                'current': session['authenticated'],
                                'require': session['userinfo'].get('login_require', 1)
                            },  'authenticated': self.is_authenticated()
                        }), 200
                    
                    if verify_value.get('code', '') and self.graph_code.pop(verify_value.get('token', '')) == verify_value.get('code', ''):
                        if self.code_checkup(2):
                            return jsonify({
                                'status': False,
                                'message': '无法重复认证',
                                'code': 402,
                                'info': {'username': username},
                                'verify': {
                                    'current': session['authenticated'],
                                    'require': session['userinfo'].get('login_require', 1)
                                },  'authenticated': self.is_authenticated()
                            }), 402
                        
                        token = self.email_code.token_gen(session['session_id'])
                        self.settings.send_code_to_email (username, '邮箱安全认证', token, int(config.expire / 60), get_client_ip())
                        return jsonify({'status': True , 'code': 200, 'info': None, 'message': '邮箱发送成功'}), 200
                    else:
                        return jsonify({'status': False, 'code': 403, 'info': None, 'message': '图形验证失败'}), 403
                
                if verify_vtype == 'email':
                    if self.code_checkup(2):
                        return jsonify({
                            'status': False,
                            'message': '无法重复认证',
                            'code': 402,
                            'info': {'username': username},
                            'verify': {
                                'current': session['authenticated'],
                                'require': session['userinfo'].get('login_require', 1)
                            },  'authenticated': self.is_authenticated()
                        }), 402
                    
                    if  self.email_code.get(str(verify_value)) == session['session_id']:
                        self.email_code.pop(str(verify_value))
                    
                        session['authenticated'] += 2; return jsonify({
                            'status': True,
                            'message': '邮箱认证成功',
                            'code': 200,
                            'info': {'username': username},
                            'verify': {
                                'current': session['authenticated'],
                                'require': session['userinfo'].get('login_require', 1)
                            },  'authenticated': self.is_authenticated()
                        }), 200
                    else:
                        return jsonify({
                            'status': False,
                            'message': '邮箱认证失败',
                            'code': 403,
                            'info': {'username': username},
                            'verify': {
                                'current': session['authenticated'],
                                'require': session['userinfo'].get('login_require', 1)
                            },  'authenticated': self.is_authenticated()
                        }), 403
                
                if verify_vtype == 'TOTP' and verify_value:
                    if self.code_checkup(4):
                        return jsonify({
                            'status': False,
                            'message': '无法重复认证',
                            'code': 402,
                            'info': {'username': username},
                            'verify': {
                                'current': session['authenticated'],
                                'require': session['userinfo'].get('login_require', 1)
                            },  'authenticated': self.is_authenticated()
                        }), 402
                    
                    if self.settings.check_user_TOTP(username, verify_value):
                        session['authenticated'] += 4; return jsonify({
                            'status': True,
                            'message': '2FA 认证成功',
                            'code': 200,
                            'info': {'username': username},
                            'verify': {
                                'current': session['authenticated'],
                                'require': session['userinfo'].get('login_require', 1)
                            },  'authenticated': self.is_authenticated()
                        }), 200
                    else:
                        return jsonify({
                            'status': False,
                            'message': '2FA 认证失败',
                            'code': 403,
                            'info': {'username': username},
                            'verify': {
                                'current': session['authenticated'],
                                'require': session['userinfo'].get('login_require', 1)
                            },  'authenticated': self.is_authenticated()
                        }), 403
            
            return jsonify({
                'status': True,
                'message': '密码认证成功',
                'code': 200,
                'info': {'username': username},
                'verify': {
                    'current': session['authenticated'],
                    'require': session['userinfo'].get('login_require', 1)
                },  'authenticated': self.is_authenticated()
            }), 200
        
        return jsonify({
            'status': False,
            'message': '用户名或密码错误',
            'code': 401,
            'info': None
        }), 401
    
    def logout(self):
        """退出登录"""
        session.pop('authenticated', None)
        session.pop('username', None)
        session.pop('login_time', None)
        session.pop('userinfo', None)
        
        return jsonify({
            'status': True,
            'message': '已退出登录',
            'code': 200,
            'info': None
        }), 200
    
    # ========== 装饰器 ==========
    
    def login_required(self, f):
        """登录验证装饰器"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not self.is_authenticated():
                # API 请求返回 JSON
                if request.path.startswith('/api/'):
                    return jsonify({
                        'status': False,
                        'message': 'Authenticated failed...',
                        'code': 401,
                        'info': None
                    }), 401
                # 页面请求重定向到首页（登录/控制台共用）
                return redirect(url_for(self.login_view))
            return f(*args, **kwargs)
        return decorated_function
    
    def high_permission_required(self, f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not self.is_authenticated():
                # API 请求返回 JSON
                if request.path.startswith('/api/'):
                    return jsonify({
                        'status': False,
                        'message': 'Authenticated failed...',
                        'code': 401,
                        'info': None
                    }), 401
                # 页面请求重定向到首页（登录/控制台共用）
                return redirect(url_for(self.login_view))
            
            if not self.is_high_permission():
                return jsonify({
                    'status': False,
                    'message': 'Permission denied...',
                    'code': 402,
                    'info': None
                }), 402
            return f(*args, **kwargs)
        return decorated_function