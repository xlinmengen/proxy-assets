import os
import re
import time
import json
import base64
import config
from flask      import Flask, Response, stream_with_context, send_from_directory, send_file, request, session, jsonify
from typing     import Union, Callable
from datetime   import timedelta
from functools  import lru_cache, wraps

from command    import rpc
from command    import utils
from command    import captcha
from command    import update_assets
from command.oidc import OIDC_Service
from command.auth import Auth

start_time = time.time()

if os.path.isfile('.debug'):
    log = utils.Debugger('Debug.log').log
else:
    log = lambda *args, **kwargs: None

# ==============================================

def get_work_time() -> int:
    return int(time.time() - start_time)

def get_client_ip():
    """获取真实客户端 IP"""
    return request.remote_addr

def check_password(password: str):
    return len(password) >= 6

def check_user() -> bool:
    try:
        authorization = request.headers.get('Authorization', '')
        if authorization and authorization.startswith("Basic "):
            uuid, shortid = base64.b64decode(authorization[6:].encode()).decode().split(':', 1)
            return auth.is_authenticated() or (uuid and shortid and auth.settings.get_user(uuid).get('shortid', '') == shortid)
    except: return auth.is_authenticated()

def get_user_uuid() -> str:
    try:
        uuid, _ = base64.b64decode(request.headers.get('Authorization', '')[6:].encode()).decode().split(':', 1)
        return session.get('userinfo', {}).get('uuid') or uuid
    except: return session.get('userinfo', {}).get('uuid', '')

def basic_authorization() -> bool:
    try:
        username = request.authorization.username
        password = request.authorization.password
        userinfo = auth.settings.get_user_by_email(username)
        return username and password and (
            userinfo.get('password'   , '') == password or
            userinfo.get('secure_code', '') == password
        )
    except: return False

def limit_content_length(get_max_length: Union[int, Callable]):
    """支持动态获取限制"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            max_length = get_max_length() if callable(get_max_length) else get_max_length
            
            content_length = request.content_length
            if content_length and content_length > max_length:
                return Response('Request entity too large', 413)
            return f(*args, **kwargs)
        decorated._limited = True
        return decorated
    return decorator

# ==============================================

auth = Auth()
oidc = OIDC_Service(
    issuer=f'https://{auth.settings.get_server_ip()}:{config.config.get('port', 1000)}',
    audience=auth.settings.get_auth().get('audience', ''),endpoint='/oauth2/token',
    authorizator=auth.a_authenticate, expires=3600
)
tokens = utils.Tokens()
keygen = utils.Key_Generator()
requests = utils.get_session()
email_code = utils.Tokens(expire = config.expire, length = 5) # code account
graph_code = utils.Tokens(expire = config.expire, length = 8) # token code

client = rpc.RPCClient(**config.rpc_config)

ddos_class = client.get_proxy('ddos')
xray_stats = client.get_proxy('xraystat')

class DDoSProtector:
    def get_stats(self) -> dict:
        return ddos_class.get_stats()
    
    def protect(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            ip = request.remote_addr

            if ddos_class.is_whitelisted(ip):
                return f(*args, **kwargs)

            if ddos_class.is_blocked(ip):
                return jsonify({'error': 'Too many requests, temporarily banned'}), 429

            if not ddos_class.check_rate_limit(ip, dict(request.headers)):
                return jsonify({'error': 'Rate limit exceeded'}), 429

            if not ddos_class.increase_concurrent(ip):
                ddos_class.decrease_concurrent(ip)
                return jsonify({'error': 'Too many concurrent connections'}), 429

            try:
                return f(*args, **kwargs)
            finally:
                ddos_class.decrease_concurrent(ip)

        return decorated

ddos = DDoSProtector()

@lru_cache(maxsize=16)
def _get_version_cached(github_url, timestamp) -> str:
    match = re.search(r"github\.com/([^/]+)/([^/]+)", github_url)
    if match: owner, repo = match.groups()
    else: return ''

    api_url = f"https://api.github.com/repos/{owner}/{repo.replace('.git', '')}/releases/latest"

    try:
        response = requests.get(api_url)
        if response.ok:
            data = response.json()
            return data.get("tag_name", '')
        else:
            return ''
    except: return ''

def get_latest_release_version(github_url) -> str:
    version = _get_version_cached(github_url, keygen.get())
    if not version:
        keygen.refresh()
        version = _get_version_cached(github_url, keygen.get())
    return version

def rebuildCert():
    auth.settings.makecert.Rebuild_Root_CA()
    auth.settings.update_frps_certs()
    
    utils.Timer(1.0, lambda: os.system('systemctl restart monitor_launcher'))

# ==============================================

app = Flask(__name__)

app.secret_key = utils.secure_code(256)
app.config.update(
    # 会话有效期
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),

    # Cookie 设置
    SESSION_COOKIE_NAME='session',
    SESSION_COOKIE_DOMAIN=None,
    SESSION_COOKIE_PATH='/',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_REFRESH_EACH_REQUEST=True,
)
app.config['MAX_CONTENT_LENGTH'] = config.max_upload_size

@app.before_request
def default_limit():
    # 检查是否有 _limited 标记
    handler = app.view_functions.get(request.endpoint) if request.endpoint else None
    if handler and getattr(handler, '_limited', False):return
    
    content_length = request.content_length
    default_max = config.nor_upload_size
    if content_length and content_length > default_max:
        return Response('Request entity too large', 413)

auth.init_app(app)

# ==============================================

# ---------- 首页/控制台共用路由 ----------
@app.route('/', methods=['GET'])
def index():
    """首页/控制台共用路由"""
    return utils.get_index('index.html' if auth.is_authenticated() else 'login.html')

@app.route('/', methods=['OPTIONS'])
@app.route('/<path:path>', methods=['OPTIONS'])
def options(path: str = ''):
    """处理预检请求"""
    response = Response()
    response.headers['DAV'  ] = '1, 2'
    response.headers['Allow'] = 'GET, HEAD, PUT, DELETE, OPTIONS, PROPFIND, MKCOL'
    response.headers['Access-Control-Max-Age'] = '86400'
    response.headers['Access-Control-Allow-Origin' ] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, HEAD, PUT, DELETE, OPTIONS, PROPFIND, MKCOL'
    response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type, Depth, If, Destination'
    return response

@app.route('/favicon.ico', methods=['GET'])
def favicon():
    if os.path.isfile('./static/Icons/favicon.ico'):
        return app.send_static_file('Icons/favicon.ico')
    else:
        return Response(b'', 200, mimetype='image/vnd.microsoft.icon')

@app.route('/monitor', methods=['GET'])
def monitor_index():
    return utils.get_index('monitor.html' if auth.is_authenticated() else 'login.html')

@app.route('/monitor/stats', methods=['POST'])
@auth.login_required
def monitor_stats():
    try:
        data = request.get_json()
        return jsonify({
            'status': True,
            'code': 200,
            'info': {
                'ddos': ddos.get_stats(),
                'system': {
                    'cpu': utils.get_system_cpu_info(interval=data.get('interval', 1), percpu=data.get('percpu', False)),
                    'memory': utils.get_system_memory_info()
                }
            }
        }), 200
    except:
        return jsonify({
            'status': False,
            'code': 401,
            'info': None,
        }), 401

@app.route('/tools', methods=['GET'])
@app.route('/tools/<path>', methods=['GET'])
def tools_index(path: str = ''):
    return utils.get_index(f'tools/{path if path else 'index'}.html' if auth.is_authenticated() else 'login.html')

# ---------- OIDC 服务路由 ----------
@app.route("/.well-known/openid-configuration", methods=['GET'])
def openid_configuration():
    return jsonify( oidc.openid_configuration() )

@app.route("/.well-known/jwks.json", methods=['GET'])
def jwks():
    return jsonify( oidc.jwks() )

@app.route("/oauth2/token", methods=['POST'])
@ddos.protect
@limit_content_length(1024 * 2 + 512)
def token_endpoint():
    try   :status = oidc.token_endpoint( request.headers.get("Authorization", "") )
    except:status = ({'error': 'invalid_client'}, False)
    return jsonify( status[0] ), ( 200 if status[1] else 401 )

# ---------- OIDC 拓展服务路由 ----------
@app.route("/oauth2/audience", methods=['POST'])
@ddos.protect
@limit_content_length(1024 * 2 + 512)
def oauth2_audience():
    try:
        status = oidc.token_endpoint( request.headers.get("Authorization", "") )

        if status[1]:
            return jsonify({
                'status': True,
                'code': 200,
                'info': auth.settings.get_auth()['audience']
            }), 200
    except:pass
    return jsonify({
        'status': False,
        'code': 401,
        'info': None
    }), 401

@app.route('/oauth2/cert', methods=['POST'])
@ddos.protect
@limit_content_length(1024 * 2 + 512)
def oauth2_cert():
    try:
        status = oidc.token_endpoint( request.headers.get("Authorization", "") )

        if status[1]: return send_from_directory('/opt/monitor/certs', 'ca.crt')
    except:pass
    return jsonify({
        'status': False,
        'code': 401,
        'info': None
    }), 401

@app.route('/oauth2/issue_cert', methods=['POST'])
@ddos.protect
@limit_content_length(1024 * 2 + 512)
def oauth2_issue_cert():
    try:
        status = oidc.token_endpoint( request.headers.get("Authorization", "") )

        if status[1]:
            data = request.get_json()
            data = {x:data[x] for x in data.keys() if x in ['domain', 'validity_days', 'TLS_Web_AType', 'IncludeCaCert']}
            if  not data.get('domain'):
                return jsonify({
                    'status': False,
                    'message': '缺少 domain 参数',
                    'code': 400,
                    'info': None
                }), 400
            try:
                return Response(
                    utils.compress_cert(*auth.settings.makecert.generate_cert(**data)),
                    mimetype='application/zip',
                    headers={
                        'Content-Disposition': f'attachment; filename=certs.zip'
                    },
                    status=200
                )
            except: return '', 502
    except:pass
    return jsonify({
        'status': False,
        'code': 401,
        'info': None
    }), 401

# ---------- FRPS API 控制接口映射 ----------
@app.route('/oauth2/frps', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/oauth2/frps/<path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@ddos.protect
@limit_content_length(1024 * 2 + 512)
def api_frps(path = ''):
    try:
        status = oidc.token_endpoint( request.headers.get("Authorization", "") )

        if status[1]:
            resp = requests.request(
                method=request.method,
                url=f'http://127.0.0.1:1020/api/{path}',
                auth=(
                    auth.settings.get_auth()['username'],
                    auth.settings.get_auth()['password']
                ),
                headers={k: v for k, v in request.headers.items() 
                        if k.lower() not in ['host', 'content-length']},
                params=request.args,
                json=request.get_json() if request.is_json else None,
                data=request.get_data() if not request.is_json else None,
                timeout=30
            );  return jsonify(resp.json()), resp.status_code
    except:pass
    return jsonify({
        'status': False,
        'code': 401,
        'info': None
    }), 401

# ---------- 重置密码界面 & API 接口 ----------
@app.route('/reset', methods=['GET'])
def reset_password_page():
    return utils.get_index('reset.html')

@app.route('/api/reset/get_email_code', methods=['POST'])
@ddos.protect
def api_reset_get_email_code():
    if not session.get('reset_verify', False):
        data = request.get_json()
        code = graph_code.pop(data.get('token', ''))
        if  code and code ==  data.get('code' , ''):
            if  auth.settings.get_user_by_email (data.get('email', '')):
                token = email_code.token_gen    (data.get('email', ''))
                auth.settings.send_code_to_email(data.get('email', ''), '恢复账户验证', token, int(config.expire / 60), get_client_ip())
            return     jsonify({'status': True , 'code': 200, 'info': None, 'message': '如果这个邮箱匹配且有效，我们将向这个邮箱发送一串代码'}), 200
        else:   return jsonify({'status': False, 'code': 400, 'info': None, 'message': '图形验证码错误'}), 400
    else:       return jsonify({'status': False, 'code': 401, 'info': None, 'message': '验证已通过，无法发送'}), 401

@app.route('/api/reset/get_graph_code', methods=['POST'])
@ddos.protect
def api_reset_get_graph_code():
    code  = utils.secure_code(5)
    token = graph_code.token_gen(code)
    graph = captcha.generator(code, bg_color=(40, 44, 52))
    return jsonify({'status': True, 'info': {'token': token, 'graph': graph}}), 200

@app.route('/api/reset/check_code', methods=['POST'])
@ddos.protect
def api_reset_check_code():
    data   = request.get_json()
    code   = data.get('code')
    email  = session.get('username', data.get('email', ''))
    status = session.get('reset_verify', False)

    if  code:
        if email and email_code.get(code) == email   : status = True
        if auth.settings.check_user_TOTP(email, code): status = True
        if  len(code) == 2048:
            uuid = auth.settings.get_user_by_email(email)['uuid']
            if  code == auth.settings.get_user_secure_code(uuid):
                status = True
    
    if  status:
        session['username'] = email
    session['reset_verify'] = status

    return jsonify({'status': status}), 200

@app.route('/api/reset/reset_account_password', methods=['POST'])
@ddos.protect
def api_reset_reset_email_password():
    data   = request.get_json()
    email  = session.get('username')
    verily = session.get('reset_verify', False)
    new_password = data.get('new_password')

    if  not email:
        return jsonify({
            'status': False,
            'message': 'Error',
            'code': 400,
            'info': None
        }), 400

    if  not new_password:
        return jsonify({
            'status': False,
            'message': '新密码不能为空',
            'code': 400,
            'info': None
        }), 400
    
    if  not check_password(new_password):
        return jsonify({
            'status': False,
            'message': '新密码不符合要求',
            'code': 400,
            'info': None
        }), 400
    
    if  verily:
        euuid = auth.settings.get_user_by_email(email)['uuid']
        auth.settings.reset_user_password(euuid, new_password)
        return jsonify({
            'status': True,
            'message': '密码修改成功',
            'code': 200,
            'info': None
        }), 200
    
    return jsonify({
        'status': False,
        'message': '认证错误',
        'code': 401,
        'info': None
    }), 401

# ---------- 静态资源 ----------
@app.route('/cert', methods=['GET'])
@auth.login_required
def get_cert():
    return send_from_directory('/opt/monitor/certs', 'ca.crt')

@app.route('/custom/<path:path>', methods=['GET'])
@ddos.protect
def get_custom(path):
    if not check_user(): return '', 404
    return auth.settings.get_user_custom_ruleset_filedata(get_user_uuid(), path)

@app.route('/custom/get/<path:path>', methods=['POST'])
@auth.login_required
def get_custom_file(path):
    return jsonify({
        'status': True,
        'message': '',
        'code': 200,
        'info': auth.settings.get_user_custom_ruleset(session.get('userinfo', {}).get('uuid', ''), path)
    })

@app.route('/custom/set/<path:path>', methods=['POST'])
@auth.login_required
@limit_content_length(1024 * 1024 * 10)  # 限制上传内容最大为 10 MB
def set_custom_file(path):
    data = request.get_json() or request.form
    ruleset = data.get('ruleset', [])
    if not isinstance(ruleset, list):
        return jsonify({'status': False, 'message': '规则集必须是一个列表', 'code': 400, 'info': None}), 400
    
    auth.settings.reset_user_custom_ruleset(session.get('userinfo', {}).get('uuid', ''), path, ruleset)
    return jsonify({'status': True, 'message': '规则集更新成功', 'code': 200, 'info': None}), 200

@app.route('/static/<path:path>', methods=['GET'])
def get_static(path):
    return app.send_static_file(path)

@app.route('/repo/<path:path>', methods=['GET'])
@auth.login_required
def get_repo(path):
    return send_from_directory('/opt/repo', path)

# ---------- 下载配置 - Token ----------
@app.route('/api/proxy/token/<path:token>', methods=['GET'])
@ddos.protect
def api_proxy_download_with_token(token):
    """通过令牌下载配置"""
    token_data = tokens.pop(token)
    if not token_data:
        return 'Invalid or expired token', 404
    
    config_data = auth.settings.generate_proxy_config(token_data)
    if not config_data:
        return 'Config not found', 404
    
    return Response(
        config_data,
        mimetype='application/x-yaml',
        headers={
            'Content-Type': 'text/plain; charset=utf-8',
            'Content-Disposition': f'attachment; filename=proxy.yaml'
        }
    )

# ---------- 登录 API ----------
@app.route('/api/login', methods=['POST'])
@ddos.protect
def api_login():
    """登录 API"""
    data = request.get_json() or request.form

    return auth.login(
        data.get('username'),
        data.get('password'),
        data.get('verify'),
        data.get('remember') == 'on' or data.get('remember') == None
    )

# ---------- 退出登录 API ----------
@app.route('/api/logout', methods=['POST'])
@auth.login_required
def api_logout():
    """退出登录 API"""
    return auth.logout()

# ---------- 登录状态 API ----------
@app.route('/api/status', methods=['POST'])
def api_status():
    """获取登录状态"""
    if auth.is_authenticated():
        return jsonify({
            'status': True,
            'message': None,
            'code': 200,
            'info': {
                'authenticated': True,
                'username': session.get('username'),
                'login_time': session.get('login_time'),
                'userinfo': session.get('userinfo'),
                'verify': session.get('verify', {})
            }
        })
    return jsonify({
        'status': True,
        'message': None,
        'code': 200,
        'info': {'authenticated': False, 'verify': session.get('verify', {})}
    })

# ---------- 设置密码 API ----------
@app.route('/api/passwd', methods=['POST'])
@auth.login_required
def api_passwd():
    """修改当前登录用户的密码"""
    data = request.get_json() or request.form
    new_password = data.get('new_password')

    if not new_password:
        return jsonify({
            'status': False,
            'message': '新密码不能为空',
            'code': 400,
            'info': None
        }), 400

    if not check_password(new_password):
        return jsonify({
            'status': False,
            'message': '新密码不符合要求',
            'code': 400,
            'info': None
        }), 400

    # 获取当前用户信息
    userinfo = session.get('userinfo')
    if not userinfo:
        return jsonify({
            'status': False,
            'message': '用户信息不存在',
            'code': 500,
            'info': None
        }), 500

    # 更新密码
    auth.settings.reset_user_password(userinfo['uuid'], new_password)
    return jsonify({
        'status': True,
        'message': '密码修改成功',
        'code': 200,
        'info': None
    })

@app.route('/api/get_user_id', methods=['POST'])
@auth.login_required
def api_get_userid():
    """获取当前用户 ID"""
    userinfo = session.get('userinfo')
    if not userinfo:
        return jsonify({
            'status': False,
            'message': '用户信息不存在',
            'code': 500,
            'info': None
        }), 500
    
    return jsonify({
        'status': True,
        'message': None,
        'code': 200,
        'info': {'user_id': auth.settings.get_user_id(userinfo['uuid'])}
    })

@app.route('/api/get_keycode', methods=['POST'])
@auth.login_required
def api_get_keycode():
    """获取当前用户的 TOTP keycode"""
    userinfo = session.get('userinfo')
    if not userinfo:
        return jsonify({
            'status': False,
            'message': '用户信息不存在',
            'code': 500,
            'info': None
        }), 500
    
    return jsonify({
        'status': True,
        'message': None,
        'code': 200,
        'info': {'keycode': auth.settings.get_user_keycode(userinfo['uuid'])}
    })

@app.route('/api/get_secure_code', methods=['POST'])
@auth.login_required
def api_get_secure_code():
    """获取当前用户的安全码"""
    userinfo = session.get('userinfo')
    if not userinfo:
        return jsonify({
            'status': False,
            'message': '用户信息不存在',
            'code': 500,
            'info': None
        }), 500

    return jsonify({
        'status': True,
        'message': None,
        'code': 200,
        'info': {'secure_code': auth.settings.get_user_secure_code(userinfo['uuid'])}
    })

@app.route('/api/get_authorization_code', methods=['POST'])
@auth.login_required
def api_get_authorization_code():
    """获取当前用户的授权码"""
    userinfo = session.get('userinfo')
    if not userinfo:
        return jsonify({
            'status': False,
            'message': '用户信息不存在',
            'code': 500,
            'info': None
        }), 500

    return jsonify({
        'status': True,
        'message': None,
        'code': 200,
        'info': {'authorization_code': auth.settings.get_user_authorization_code(userinfo['uuid'])}
    })


@app.route('/api/get_login_require', methods=['POST'])
@auth.login_required
def api_get_login_require():
    """获取当前用户的登录要求"""
    userinfo = session.get('userinfo')
    if not userinfo:
        return jsonify({
            'status': False,
            'message': '用户信息不存在',
            'code': 500,
            'info': None
        }), 500

    return jsonify({
        'status': True,
        'message': None,
        'code': 200,
        'info': {'login_require': auth.settings.get_user_login_require(userinfo['uuid'])}
    })

@app.route('/api/reset_login_require', methods=['POST'])
@auth.login_required
def api_reset_login_require():
    data = request.get_json() or request.form
    require = data.get('require')

    userinfo = session.get('userinfo')
    if not userinfo:
        return jsonify({
            'status': False,
            'message': '用户信息不存在',
            'code': 500,
            'info': None
        }), 500

    if require not in [1, 3, 5, 7]:
        return jsonify({
            'status': False,
            'message': '登录要求设置错误',
            'code': 400,
            'info': None
        }), 400

    auth.settings.reset_user_login_require(userinfo['uuid'], require)
    return jsonify({
        'status': True,
        'message': '登录要求重置成功',
        'code': 200,
        'info': None
    })

@app.route('/api/reset_secure_code', methods=['POST'])
@auth.login_required
def api_reset_secure_code():
    userinfo = session.get('userinfo')
    if not userinfo:
        return jsonify({
            'status': False,
            'message': '用户信息不存在',
            'code': 500,
            'info': None
        }), 500

    secure_code = auth.settings.reset_user_secure_code(userinfo['uuid'])
    return jsonify({
        'status': True,
        'message': '安全码重置成功',
        'code': 200,
        'info': {'secure_code': secure_code}
    })

@app.route('/api/reset_authorization_code', methods=['POST'])
@auth.login_required
def api_reset_authorization_code():
    userinfo = session.get('userinfo')
    if not userinfo:
        return jsonify({
            'status': False,
            'message': '用户信息不存在',
            'code': 500,
            'info': None
        }), 500

    authorization_code = auth.settings.reset_user_authorization_code(userinfo['uuid'])
    return jsonify({
        'status': True,
        'message': '授权码重置成功',
        'code': 200,
        'info': {'authorization_code': authorization_code}
    })

@app.route('/api/check_TOTP', methods=['POST'])
@auth.login_required
def api_check_TOTP():
    """验证 TOTP 代码"""
    data = request.get_json() or request.form
    code = data.get('code', '')

    userinfo = session.get('userinfo')
    if not userinfo:
        return jsonify({
            'status': False,
            'message': '用户信息不存在',
            'code': 500,
            'info': None
        }), 500

    email = userinfo.get('email')
    if auth.settings.check_user_TOTP(email, code):
        session['verify'] = {'TOTP': True}
        return jsonify({
            'status': True,
            'message': '验证成功',
            'code': 200,
            'info': None
        })
    else:
        return jsonify({
            'status': False,
            'message': '验证失败',
            'code': 401,
            'info': None
        }), 401

@app.route('/api/reset_TOTP_keycode', methods=['POST'])
@auth.login_required
def reset_TOTP_keycode():
    """重置 TOTP keycode"""
    userinfo = session.get('userinfo')
    if not userinfo:
        return jsonify({
            'status': False,
            'message': '用户信息不存在',
            'code': 500,
            'info': None
        }), 500

    new_keycode = auth.settings.reset_user_keycode(userinfo['uuid'])
    return jsonify({
        'status': True,
        'message': 'TOTP keycode 重置成功',
        'code': 200,
        'info': {'keycode': new_keycode}
    })

# ---------- 获取配置 API ----------
@app.route('/api/proxy', methods=['POST'])
@auth.login_required
def api_get_proxy_config():
    """获取当前登录用户的代理配置"""
    userinfo = session.get('userinfo')
    if not userinfo:
        return jsonify({
            'status': False,
            'message': '用户信息不存在',
            'code': 500,
            'info': None
        }), 500

    config_data = auth.settings.generate_proxy_config(userinfo['uuid'])
    if not config_data:
        return jsonify({
            'status': False,
            'message': '生成配置失败',
            'code': 500,
            'info': None
        }), 500

    return jsonify({
        'status': True,
        'message': None,
        'code': 200,
        'info': {'config': config_data, 'email': userinfo['email']}
    })

@app.route('/api/proxy/token', methods=['POST'])
@auth.login_required
def api_proxy_token():
    """获取临时下载令牌"""
    userinfo = session.get('userinfo')
    if not userinfo:
        return jsonify({'status': False, 'message': '未登录'}), 401
    
    return jsonify({
        'status' : True,
        'message': None,
        'code': 200,
        'info': {'token': tokens.token_gen(userinfo['uuid'])}
    })

# ---------- 管理功能 API ----------
@app.route('/api/user/proxy/token/<uuid>', methods=['POST'])
@auth.login_required
@auth.high_permission_required
def api_user_proxy_token(uuid):
    """管理员获取指定用户的令牌"""
    return jsonify({
        'status' : True,
        'message': None,
        'code': 200,
        'info': {'token': tokens.token_gen(uuid)}
    })

@app.route('/api/user/list', methods=['POST'])
@auth.login_required
@auth.high_permission_required
def api_get_users():
    """获取所有用户列表"""
    traffic_data = xray_stats.get_all_users_traffic()
    users = auth.settings.get_users()

    for uuid, user_info in users.items():
        email = user_info.get('email')
        if email and email in traffic_data:
            user_traffic = traffic_data[email]
            users[uuid]['accumulated'] = user_traffic.get('accumulated', {'uplink': 0, 'downlink': 0})
            users[uuid]['speed'] = user_traffic.get('speed', {'uplink': 0, 'downlink': 0})
    
    return jsonify({
        'status': True,
        'message': None,
        'code': 200,
        'info': {'users': users}
    })

@app.route('/api/user/proxy', methods=['POST'])
@auth.login_required
@auth.high_permission_required
def api_get_user_proxy_config():
    """获取指定用户的代理配置（管理员）"""
    data = request.get_json() or request.form
    user_uuid = data.get('uuid')
    user_info = auth.settings.get_users().get(user_uuid, {})
    if not user_uuid:
        return jsonify({
            'status': False,
            'message': '缺少用户UUID',
            'code': 400,
            'info': None
        }), 400

    config_data = auth.settings.generate_proxy_config(user_uuid)
    if not config_data:
        return jsonify({
            'status': False,
            'message': '生成配置失败',
            'code': 500,
            'info': None
        }), 500

    return jsonify({
        'status': True,
        'message': None,
        'code': 200,
        'info': {'config': config_data, 'uuid': user_uuid, 'email': user_info.get('email')}
    })

@app.route('/api/user/create', methods=['POST'])
@auth.login_required
@auth.high_permission_required
def api_create_user():
    """创建新用户（需要高权限）"""
    data = request.get_json() or request.form
    email = data.get('email')
    password = data.get('password')
    description = data.get('description', '')

    level_str = data.get('level', '1,2')
    try:
        user_level, xray_level = map(int, level_str.split(','))
    except:
        return jsonify({
            'status': False,
            'message': '等级格式错误，应为 "user_level,xray_level"',
            'code': 400,
            'info': None
        }), 400

    if not email or not password:
        return jsonify({
            'status': False,
            'message': '邮箱和密码不能为空',
            'code': 400,
            'info': None
        }), 400

    if not check_password(password):
        return jsonify({
            'status': False,
            'message': '密码不符合要求',
            'code': 400,
            'info': None
        }), 400

    if auth.settings.get_user_by_email(email):
        return jsonify({
            'status': False,
            'message': '邮箱已存在',
            'code': 409,
            'info': None
        }), 409

    auth.settings.create_user(email, password, (user_level, xray_level), description)
    new_user = auth.settings.get_user_by_email(email)
    return jsonify({
        'status': True,
        'message': '用户创建成功',
        'code': 200,
        'info': {'uuid': new_user.get('uuid'), 'info': new_user}
    })

@app.route('/api/user/delete', methods=['POST'])
@auth.login_required
@auth.high_permission_required
def api_delete_user():
    """删除用户"""
    data = request.get_json() or request.form
    user_uuid = data.get('uuid')
    if not user_uuid:
        return jsonify({
            'status': False,
            'message': '缺少用户UUID',
            'code': 400,
            'info': None
        }), 400

    current_uuid = session.get('userinfo', {}).get('uuid')
    if current_uuid == user_uuid:
        return jsonify({
            'status': False,
            'message': '不能删除当前登录用户',
            'code': 403,
            'info': None
        }), 403

    auth.settings.delete_user(user_uuid)
    return jsonify({
        'status': True,
        'message': '用户删除成功',
        'code': 200,
        'info': {}
    })

@app.route('/api/user/id', methods=['POST'])
@auth.login_required
@auth.high_permission_required
def api_reset_user_id():
    """重置用户 UUID 和 shortid"""
    data = request.get_json() or request.form
    user_uuid = data.get('uuid')
    if not user_uuid:
        return jsonify({
            'status': False,
            'message': '缺少用户UUID',
            'code': 400,
            'info': None
        }), 400

    user_uuid = auth.settings.reset_user_id(user_uuid)
    user_info = auth.settings.get_users().get(user_uuid, {})
    return jsonify({
        'status': True,
        'message': '重置用户ID成功',
        'code': 200,
        'info': {'uuid': user_uuid, 'info': user_info}
    })

@app.route('/api/user/email', methods=['POST'])
@auth.login_required
@auth.high_permission_required
def api_reset_user_email():
    """重置用户邮箱"""
    data = request.get_json() or request.form
    user_uuid = data.get('uuid')
    new_email = data.get('email')
    if not user_uuid or not new_email:
        return jsonify({
            'status': False,
            'message': '缺少用户UUID或新邮箱',
            'code': 400,
            'info': None
        }), 400

    # 检查新邮箱是否已被其他用户使用
    existing = auth.settings.get_user_by_email(new_email)
    if existing and existing['uuid'] != user_uuid:
        return jsonify({
            'status': False,
            'message': '邮箱已被占用',
            'code': 409,
            'info': None
        }), 409

    auth.settings.reset_user_email(user_uuid, new_email)
    user_info = auth.settings.get_users().get(user_uuid, {})
    return jsonify({
        'status': True,
        'message': '用户邮箱重置成功',
        'code': 200,
        'info': {'uuid': user_uuid, 'info': user_info}
    })

@app.route('/api/user/passwd', methods=['POST'])
@auth.login_required
@auth.high_permission_required
def api_reset_user_passwd():
    """管理员重置用户密码"""
    data = request.get_json() or request.form
    user_uuid = data.get('uuid')
    new_password = data.get('password')
    if not user_uuid or not new_password:
        return jsonify({
            'status': False,
            'message': '缺少用户UUID或新密码',
            'code': 400,
            'info': None
        }), 400

    auth.settings.reset_user_password(user_uuid, new_password)
    user_info = auth.settings.get_users().get(user_uuid, {})
    return jsonify({
        'status': True,
        'message': '用户密码重置成功',
        'code': 200,
        'info': {'uuid': user_uuid, 'info': user_info}
    })

@app.route('/api/user/description', methods=['POST'])
@auth.login_required
@auth.high_permission_required
def api_reset_user_description():
    """重置用户描述"""
    data = request.get_json() or request.form
    user_uuid = data.get('uuid')
    description = data.get('description', '')
    if not user_uuid:
        return jsonify({
            'status': False,
            'message': '缺少用户UUID',
            'code': 400,
            'info': None
        }), 400

    auth.settings.reset_user_description(user_uuid, description)
    user_info = auth.settings.get_users().get(user_uuid, {})
    return jsonify({
        'status': True,
        'message': '用户描述设置成功',
        'code': 200,
        'info': {'uuid': user_uuid, 'info': user_info}
    })

@app.route('/api/user/level', methods=['POST'])
@auth.login_required
@auth.high_permission_required
def api_reset_user_level():
    """重置用户等级"""
    data = request.get_json() or request.form
    user_uuid = data.get('uuid')
    level_str = data.get('level')
    if not user_uuid or not level_str:
        return jsonify({
            'status': False,
            'message': '缺少用户UUID或等级',
            'code': 400,
            'info': None
        }), 400

    try:
        user_level, xray_level = map(int, level_str.split(','))
    except:
        return jsonify({
            'status': False,
            'message': '等级格式错误，应为 "user_level,xray_level"',
            'code': 400,
            'info': None
        }), 400

    auth.settings.reset_user_level(user_uuid, (user_level, xray_level))
    user_info = auth.settings.get_users().get(user_uuid, {})

    return jsonify({
        'status': True,
        'message': '用户等级重置成功',
        'code': 200,
        'info': {'uuid': user_uuid, 'info': user_info}
    })

@app.route('/api/auth/info', methods=['POST'])
@auth.login_required
@auth.high_permission_required
def api_get_auth_info():
    """获取认证信息"""
    return jsonify({
        'status': True,
        'message': None,
        'code': 200,
        'info': auth.settings.get_auth()
    })

@app.route('/api/auth/audience', methods=['POST'])
@auth.login_required
@auth.high_permission_required
def api_reset_auth_audience():
    """重置 API 受众认证"""
    auth.settings.reset_auth_audience()
    audience = auth.settings.get_auth().get('audience')
    oidc.reset_audience(audience)
    return jsonify({
        'status': True,
        'message': 'API 受众认证重置成功',
        'code': 200,
        'info': {'audience': audience}
    })

@app.route('/api/auth/admin', methods=['POST'])
@auth.login_required
@auth.high_permission_required
def api_reset_auth_admin():
    """重置管理员账号密码"""
    data = request.get_json() or request.form
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({
            'status': False,
            'message': '用户名和密码不能为空',
            'code': 400,
            'info': None
        }), 400

    if not check_password(password):
        return jsonify({
            'status': False,
            'message': '密码不符合要求',
            'code': 400,
            'info': None
        }), 400

    auth.settings.reset_auth(username, password)
    return jsonify({
        'status': True,
        'message': '管理员账号重置成功',
        'code': 200,
        'info': {'username': username}
    })

# ---------- SMTP 配置 API ----------
@app.route('/api/smtp/reset', methods=['POST'])
@auth.login_required
@auth.high_permission_required
def api_smtp_reset():
    auth.settings.reset_smtp_account(**request.get_json())
    return jsonify({
        'status': True,
        'message': 'SMTP 配置修改成功',
        'code': 200,
        'info': None
    })

@app.route('/api/smtp/check', methods=['POST'])
@auth.login_required
@auth.high_permission_required
def api_smtp_check():
    userinfo = session.get('userinfo')
    status = auth.settings.check_smtp_account(userinfo['email'])
    return jsonify({
        'status': status,
        'message': '使用当前配置' + ('成功发送邮件' if status else '发送邮件失败'),
        'code': 200 if status else 400,
        'info': None
    }), 200 if status else 400

@app.route('/api/smtp/setting', methods=['POST'])
@auth.login_required
@auth.high_permission_required
def api_smtp_setting():
    return jsonify({
        'status' : True,
        'message': None,
        'code': 200,
        'info': auth.settings.get_smtp()
    }), 200

@app.route('/api/smtp/support', methods=['POST'])
def api_smtp_support():
    status = auth.settings.check_smtp_setting()
    return jsonify({
        'status': status,
    }), 200 if status else 400

# ---------- Warn 配置 API ----------
@app.route('/api/warn/get_threshold', methods=['POST'])
@auth.login_required
@auth.high_permission_required
def api_warn_get_threshold():
    return jsonify({
        'status' : True,
        'message': None,
        'code': 200,
        'info': auth.settings.get_monitor()
    }), 200 

@app.route('/api/warn/set_threshold', methods=['POST'])
@auth.login_required
@auth.high_permission_required
def api_warn_set_threshold():
    data = request.get_json()
    auth.settings.reset_monitor_config(data)
    
    return jsonify({
        'status' : True,
        'message': None,
        'code': 200,
        'info': auth.settings.get_monitor()
    }), 200 

# ---------- Cert 管理 API ----------
@app.route('/api/cert/info', methods=['POST'])
@auth.login_required
def api_cert_info():
    begin_timestamp, after_timestamp = auth.settings.makecert.get_ca_time()
    remain_seconds = after_timestamp - time.time()
    is_available   = after_timestamp - time.time() > 0
    
    return jsonify({
        'status': True,
        'message': None,
        'code': 200,
        'info': {
            'begin_timestamp': begin_timestamp,
            'after_timestamp': after_timestamp,
            'remain_seconds' : remain_seconds ,
            'is_available'   : is_available
        }
    }), 200

@app.route('/api/cert/service', methods=['POST'])
@auth.login_required
def api_cert_service():
    data = request.get_json()
    data = {x:data[x] for x in data.keys() if x in ['domain', 'validity_days', 'TLS_Web_AType', 'IncludeCaCert']}
    
    if  not data.get('domain'):
        return jsonify({
            'status': False,
            'message': '缺少 domain 参数',
            'code': 400,
            'info': None
        }), 400
    try:
        return Response(
            utils.compress_cert(*auth.settings.makecert.generate_cert(**data)),
            mimetype='application/zip',
            headers={
                'Content-Disposition': f'attachment; filename=certs.zip'
            },
            status=200
        )
    except: return '', 502

@app.route('/api/cert/rebuild', methods=['POST'])
@auth.login_required
@auth.high_permission_required
def api_cert_rebuild():
    rebuildCert();return jsonify({
        'status': True,
        'message': '根 CA 证书已重置',
        'code': 200,
        'info': None
    }), 200

# ---------- Time 设置 API ----------
@app.route('/api/time/get_offset', methods=['POST'])
@auth.login_required
def api_time_get_offset():
    uuid = session.get('userinfo')['uuid']
    return jsonify({
        'status': True,
        'message': None,
        'code': 200,
        'info': {'offset': auth.settings.get_time_offset(uuid)}
    })

@app.route('/api/time/set_offset', methods=['POST'])
@auth.login_required
def api_time_set_offset():
    data = request.get_json()
    uuid = session.get('userinfo')['uuid']
    auth.settings.set_time_offset(uuid, data.get('offset', 0))
    return jsonify({
        'status': True,
        'message': "偏移设置完成",
        'code': 200,
        'info': None
    })

# ---------- 网络测速 API ----------
@app.route('/api/byte', methods=['POST'])
@limit_content_length(1024 * 1024 * 1024 * 10)
@auth.login_required
def api_byte():
    if  auth.is_high_permission():
        gen_size = min(max(request.get_json().get('size', 1024), 1024), 1024*1024*100)
        gen_time = min(max(request.get_json().get('time', 10  ), 0   ), 3600)
    else:
        gen_size = min(max(request.get_json().get('size', 1024), 1024), 1024*1024*10)
        gen_time = min(max(request.get_json().get('time', 10  ), 0   ), 60)
    
    if  gen_time == 0:
        return Response(b'', status=200, headers={
            'Content-Type': 'application/octet-stream',
            'X-Chunk-Size': '0',
            'X-Duration': '0'
        })
    
    if  request.get_json().get('direction', 'down') == 'up':
        @stream_with_context
        def up_content_generator():
            start_time = time.time()
            received = 0
            
            while time.time() - start_time < gen_time:
                data = request.stream.read(gen_size)
                if not data: break
                received += len(data)
            
            yield json.dumps({'received': received}).encode()
        
        return Response(
            up_content_generator(),
            status=200,
            headers={
                'Content-Type': 'application/json',
                'Cache-Control': 'no-cache'
            }
        )
    else:
        @stream_with_context
        def bcontent_generator():
            gen_start_time = time.time()
            while time.time() - gen_start_time < gen_time:
                yield utils.secure_code(gen_size).encode()
        
        return Response(
            bcontent_generator(),
            status=200,
            headers={
                'Content-Type': 'application/octet-stream',
                'X-Chunk-Size': str(gen_size),
                'X-Duration'  : str(gen_time),
                'Cache-Control': 'no-cache'
            }
        )

# ---------- Xray 统计 API ----------
@app.route('/api/xray/traffic', methods=['POST'])
@auth.login_required
def api_xray_traffic():
    """获取当前用户流量（累计 + 实时速度）"""
    userinfo = session.get('userinfo')
    if not userinfo:
        return jsonify({
            'status': False,
            'message': '用户信息不存在',
            'code': 500,
            'info': None
        }), 500

    traffic = xray_stats.get_user_traffic(userinfo['email'])
    
    accumulated = traffic.get('accumulated', {'uplink': 0, 'downlink': 0})
    speed = traffic.get('speed', {'uplink': 0, 'downlink': 0})

    return jsonify({
        'status': True,
        'message': None,
        'code': 200,
        'info': {
            'speed': speed,
            'email': userinfo['email'],
            'accumulated': accumulated
        }
    })

@app.route('/api/xray/all-traffic', methods=['POST'])
@auth.login_required
@auth.high_permission_required
def api_xray_all_traffic():
    """获取所有用户流量（管理员）"""
    traffic_data = xray_stats.get_all_users_traffic()
    
    total_up = 0
    total_down = 0
    
    result = {}
    for email, data in traffic_data.items():
        accumulated = data.get('accumulated', {'uplink': 0, 'downlink': 0})
        speed = data.get('speed', {'uplink': 0, 'downlink': 0})
        
        total_up += accumulated.get('uplink', 0)
        total_down += accumulated.get('downlink', 0)
        
        result[email] = {
            'speed': speed,
            'accumulated': accumulated
        }
    
    return jsonify({
        'status': True,
        'message': None,
        'code': 200,
        'info': {
            'traffic': result,  # 格式 {email: {uplink, downlink}}
            'total': {
                'uplink': total_up,
                'downlink': total_down
            }
        }
    })

@app.route('/api/xray/sys-stats', methods=['POST'])
@auth.login_required
@auth.high_permission_required
def api_xray_sys_stats():
    """获取系统统计"""
    stats = xray_stats.get_system_stats()
    stats['uptime'] = get_work_time()
    stats['memory'] = utils.get_system_memory_info()['used']

    return jsonify({
        'status': True,
        'message': None,
        'code': 200,
        'info': stats
    })

# ---------- 资产路由 ----------
@app.route('/assets', methods=['GET'])
def assets_page():
    return utils.get_index('assets.html' if auth.is_authenticated() else 'login.html')

@app.route('/assets/<name>', methods=['GET'])
@ddos.protect
def get_assets(name):
    if not check_user() and not auth.is_authenticated(): return '', 404
    url = config.LINK.get(name)
    if not url: return 'Invalid asset name', 404

    if '{}' in url:
        version = get_latest_release_version(url)
        if version: url = url.format(version, version[1:] if version.lower().startswith('v') else version) if url.count('{}') == 2 else url.replace('{}', version)
        else:
            keygen.refresh()
            return 'Upstream error: Can not get the latest version', 502

    try:
        response = requests.get(url, stream=True, timeout=(5, 60), allow_redirects=True)

        if not response.ok:
            assets_file = update_assets.get_assets_filepath(name)
            if assets_file:
                try:return send_file(assets_file, as_attachment=True, download_name=url.split('/')[-1], conditional=True)
                except:pass
            return f"Upstream error: {response.status_code}", 502

        try:raw_len = int(response.headers.get('Content-Length'))
        except:raw_len = 0

        res_headers = dict(request.headers) | utils.get_res_headers(raw_len, url.split('/')[-1])

        @stream_with_context
        def generate_chunk():
            for chunk in response.iter_content(chunk_size=config.chunk_size):
                if chunk: yield chunk
            response.close()
        return Response(generate_chunk(), status=response.status_code, headers=res_headers)

    except: return 'Upstream Timeout or Connection Error', 504