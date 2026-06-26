# Monitor Service Configure

source = 'xlinmengen/proxy-assets'
config = {
    'host': '0.0.0.0',
    'port': 1000,
    'workers': 1,
    'threads': 4
}
rpc_config = {
    'host': '127.0.0.1',
    'port': 1001
}
expire:int = 300
chunk_size = 64 * 1024
max_upload_size = 1024 * 1024 * 1024 * 10  # 10 GB
nor_upload_size = 512                      # 512 B
anisette_u = "http://127.0.0.1:30"
ddos_config= {
    'rate_limit': 120,
    'block_time': 300,
    'concurrent_limit': 20
}
LINK = {
    # MetaCubeX & P3TERX 数据库
    'asn'    : 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb',
    'city'   : 'https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-City.mmdb',
    'geoip'  : 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat',
    'geosite': 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat',
    'country': 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country.mmdb',
    # 规则集（Rule-Sets）
    'proxy' : 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt',
    'cncidr': 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/cncidr.txt',
    'direct': 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt',
    'reject': 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt',
    # 代理工具
    'yume': 'https://github.com/YumeYucca/YumeBox/releases/download/{}/YumeBox-arm64-v8a-release.apk',
    'cvfw': 'https://github.com/clash-verge-rev/clash-verge-rev/releases/download/{}/Clash.Verge_{}_x64-setup.exe',
    'cvfw_wv2': 'https://github.com/clash-verge-rev/clash-verge-rev/releases/download/{}/Clash.Verge_{}_x64_fixed_webview2-setup.exe',
    'cvfwarm' : 'https://github.com/clash-verge-rev/clash-verge-rev/releases/download/{}/Clash.Verge_{}_arm64-setup.exe',
    'cvfwarm_wv2': 'https://github.com/clash-verge-rev/clash-verge-rev/releases/download/{}/Clash.Verge_{}_arm64_fixed_webview2-setup.exe',
    'cvfl'       : 'https://github.com/clash-verge-rev/clash-verge-rev/releases/download/{}/Clash.Verge_{}_amd64.deb',
    'cvflarm'    : 'https://github.com/clash-verge-rev/clash-verge-rev/releases/download/{}/Clash.Verge_{}_arm64.deb',
    'cvfm'       : 'https://github.com/clash-verge-rev/clash-verge-rev/releases/download/{}/Clash.Verge_{}_aarch64.dmg',
    'cvfm_intel' : 'https://github.com/clash-verge-rev/clash-verge-rev/releases/download/{}/Clash.Verge_{}_x64.dmg'
}