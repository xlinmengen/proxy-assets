import os, sys, config
from command import rpc
from pathlib import Path
from command import mkcert

makecerts = mkcert.makecerts()

if __name__ == '__main__':
    client = rpc.RPCClient(**config.rpc_config)
    settings = client.get_proxy('settings')

    root = Path('/opt/monitor')
    root.mkdir(exist_ok=True, parents=True)

    cert_path = root / 'certs/service'
    cert_path.mkdir(exist_ok=True, parents=True)
    priv_data, cert_data = makecerts.generate_cert(settings.get_server_ip(), TLS_Web_AType="SERVER", IncludeCaCert=True)
    with open(cert_path / 'cert.crt', 'wb') as f: f.write(cert_data)
    with open(cert_path / 'cert.key', 'wb') as f: f.write(priv_data)

    command = "/usr/bin/python -m granian --interface wsgi"
    command += " --working-dir " + str(root)
    command += " --host " + config.config.get('host', '0.0.0.0')
    command += " --port " + str(config.config.get('port', 1000))
    command += " --ssl-certificate " + str(cert_path / 'cert.crt')
    command += " --ssl-keyfile " + str(cert_path / 'cert.key')
    command += " --workers " + str(config.config.get('workers', 1))
    command += " --runtime-mode mt"
    command += " --runtime-threads 2"
    command += " --blocking-threads " + str(config.config.get('threads', 4))
    command += " --log-level warning"
    command += " worker:app"

    try:os.system(command)
    except:sys.exit()