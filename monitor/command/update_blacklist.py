import os, time
import requests
import ipaddress
import threading

def is_valid_ip(ip):
    try:ipaddress.ip_address(ip)
    except:return False
    else  :return True

def Timer(interval: float, function: callable, args = None, kwargs = None):
    thread = threading.Timer(interval, function, args, kwargs)
    thread.daemon = True
    thread.start()

class Updater:
    url_list = (
        "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
        "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
    )
    def __init__(self):
        os.system('apt install ipset >/dev/null 2>&1')
        if  os.path.isfile('/opt/ipset.conf'):
            os.system('ipset restore -exist < /opt/ipset.conf')
        else:
            os.system('ipset create -exist blacklist hash:ip hashsize 4096 maxelem 65536')
            os.system('ipset save > /opt/ipset.conf')
        
        threading.Thread(target=self.__thread__, daemon=True).start()
    
    def save(self):
        os.system('ipset save > /opt/ipset.conf')
    
    def add(self, ip:str):
        os.system(f'ipset add -exist blacklist {ip} >/dev/null 2>&1')
    
    def __thread__(self):
        for url in self.url_list:
            try:
                r = requests.get(url, timeout=30)
                if r.status_code == 200:
                    for line in r.text.splitlines():
                        line = line.strip()
                        if not line or line.startswith('#'): continue
                        ip = line.split(' ', 1)[0].split('\t', 1)[0].strip()
                        if is_valid_ip(ip): self.add(ip);time.sleep(100)
            except Exception as e:
                print(f"Failed to fetch {url}: {e}")
        
        self.save();Timer(86400, self.__thread__)