import os,sys
import signal
import config
import psutil
from command import rpc
from command import ddos
from command import utils
from command import settings
from command import xray_stats
from command import update_assets
from command import update_blacklist

xsettings = settings.Settings()
xraystats = xray_stats.XrayStats()
server_ip = xsettings.get_server_ip()
DDoSProtector = ddos.DDoSProtector(**config.ddos_config)
DDoSProtector.whitelist_add(server_ip)

def linear_map(value: float, from_range: tuple[float, float], to_range: tuple[float, float]) -> float:
    from_min, from_max = min(*from_range), max(*from_range)
    to_min  , to_max   = min(*to_range)  , max(*to_range)
    if from_max == from_min:
        return to_min
    else:
        return to_min + (value - from_min) / (from_max - from_min) * (to_max - to_min)

def get_system_load() -> float:
    cpu = psutil.cpu_percent(interval=0.1) / 100.0
    mem = psutil.virtual_memory().percent / 100.0
    return cpu * 0.6 + mem * 0.4

def rebuildCert():
    xsettings.makecert.Rebuild_Root_CA()
    xsettings.update_frps_certs()
    
    utils.Timer(1.0, lambda: os.system('systemctl restart monitor_launcher'))

def TCreator(ctype:int = 0):
    if ctype in (0, 1):
        if  not xsettings.makecert.ca_is_available():
            rebuildCert()
        utils.Timer(60.0, TCreator, args=(1,))
    if ctype in (0, 2):
        DDoSProtector.set_overall_rate_limit(1 - linear_map(max(get_system_load(), 0.2), (0.2, 1), (0, 1)))
        utils.Timer(4.0 , TCreator, args=(2,))

if __name__ == '__main__':
    service = rpc.RPCServer(**config.rpc_config)
    service.register("settings", xsettings)
    service.register("xraystat", xraystats)
    service.register("ddos", DDoSProtector)

    update_assets.updater(server_ip)
    update_blacklist.Updater()

    os.system('systemctl restart monitor_launcher')

    def handler():
        os.system('systemctl stop monitor_launcher')
        sys.exit()

    signal.signal(signal.SIGINT , handler)
    signal.signal(signal.SIGTERM, handler)

    try  :TCreator();service.serve_forever()
    except:handler()