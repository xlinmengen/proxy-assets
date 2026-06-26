import time
import logging
from pathlib   import Path
from threading import Thread

from utils  import get_session
from config import source, config, LINK

base = Path('database')
base.mkdir(exist_ok=True)

custom_ruleset_base = Path('datas/custom')
custom_ruleset_base.mkdir(exist_ok=True)

assets_keys = ['asn', 'city', 'geoip', 'geosite', 'country', 'cncidr', 'direct', 'proxy', 'reject']
assets_list = {key: LINK[key].split('/')[-1] for key in assets_keys if key in LINK}

custom_ruleset_link = f'https://raw.githubusercontent.com/{source}/main/ruleset'
custom_ruleset_list = ['proxy.yaml','direct.yaml','reject.yaml']

def download_file(session, url, local_path, verify = True):
    try:
        resp = session.get(url, stream=True, timeout=30, verify=verify)
        if  resp.ok:
            temp_path = local_path.with_suffix('.temp')
            with open(temp_path, 'wb') as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk: f.write(chunk)
                        
            temp_path.rename(local_path)
            logging.info(f"[Updater] 已更新: {local_path.name}")
        else:
            logging.warning(f"[Updater] 下载失败 {local_path.name}: HTTPS {resp.status_code}")
    except Exception as e:
        logging.error(f"[Updater] 处理 {local_path.name} 时出错: {e}")

def updater(server_ip: str, custom_interval: float = 1200, assets_interval: float = 3600):
    """
    启动后台线程，定期从本地资产服务器下载最新文件并保存到数据库目录。
    :param interval: 更新间隔（秒）
    :return: 线程对象（已启动）
    """
    def updater_function_custom():
        session = get_session()

        time.sleep(10)

        while True:
            for item in  custom_ruleset_list:
                url = f"{custom_ruleset_link}/{item}"
                local_path = custom_ruleset_base / item
                download_file(session, url, local_path)
            time.sleep(custom_interval)
    def updater_function_assets():
        session = get_session()
        
        host = config.get('host', '0.0.0.0')
        host = {'0.0.0.0': server_ip}.get(host, host)
        base_url = f"https://{host}:{config.get('port', 1000)}"
        
        time.sleep(10)
        
        while True:
            for item, filename in assets_list.items():
                url = f"{base_url}/assets/{item}"
                local_path = base / filename
                download_file(session, url, local_path)
            time.sleep(assets_interval)

    Thread(target=updater_function_custom, daemon=True).start()
    Thread(target=updater_function_assets, daemon=True).start()

def get_assets_filepath(item: str) -> str:
    """
    获取指定资产项的本地文件路径，如果文件不存在则返回空字符串。
    """
    if item in assets_list:
        local_path = base / assets_list[item]
        return str(local_path) if local_path.exists() else ''
    return ''