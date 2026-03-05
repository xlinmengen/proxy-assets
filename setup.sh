#!/bin/bash
sudo hostnamectl set-hostname server

echo "PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '" >>~/.bashrc

###################################################

RED='\033[0;31m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
FL='\033[1A\r\033[K'
NC='\033[0m'

ICON_PROMPT="🔹"
ICON_ERROR="❌"

# ========== 解析 xray x25519 输出 ==========
parse_xray_keys() {
    local output
    local private_key=""
    local public_key=""

    output=$(xray x25519 2>/dev/null)
    
    while IFS= read -r line; do
        case "$line" in
            PrivateKey:*)
                private_key="${line#*: }"
                ;;
            Password:*)
                public_key="${line#*: }"
                ;;
        esac
    done <<< "$output"
    
    privatekey="$private_key"
    passwordkey="$public_key"
}

entry() {
    local prompt=$1
    local default=$2
    local validator=$3
    local response=""
    local message=""
    local message_color=""

    while true; do
        # 显示提示
        echo -ne "${CYAN}${ICON_PROMPT} ${prompt}${NC}" >&2
        if [ -n "$default" ]; then
            echo -ne " ${YELLOW}[默认: $default]${NC}">&2
        fi
        echo -ne ": ${CYAN}" >&2
        
        read response
        
        # 空输入处理
        if [ -z "$response" ]; then
            if [ -n "$default" ]; then
                message="${prompt}${NC}: ${YELLOW}$default"
                echo -e "${FL}${CYAN}${ICON_PROMPT} ${message}${NC}" >&2
                echo "$default"
                return 0
            else
                message="输入不能为空"
                echo -e "${FL}${RED}${ICON_ERROR} ${message}${NC}" >&2
                continue
            fi
        fi
        
        # 验证输入
        if [ -n "$validator" ]; then
            if eval "$validator \"\$response\""; then
                # 验证通过，覆盖显示成功信息
                message="${prompt}${NC}: ${YELLOW}$response"
                echo -e "${FL}${CYAN}${ICON_PROMPT} ${message}${NC}" >&2
                echo "$response"
                return 0
            else
                # 验证失败，覆盖显示错误信息
                message="无效输入值${NC}: ${CYAN}$response"
                echo -e "${FL}${RED}${ICON_ERROR} ${message}${NC}" >&2
                continue
            fi
        else
            # 无验证，覆盖显示成功信息
            message="${prompt}${NC}: ${YELLOW}$response"
            echo -e "${FL}${CYAN}${ICON_PROMPT} ${message}${NC}" >&2
            echo "$response"
            return 0
        fi
    done
}

validate_email() {
    local email=$1
    [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]
}

validate_password() {
    local password=$1
    local min_len=${2:-6}
    [ ${#password} -ge $min_len ]
}

###################################################

email=$(entry "请输入邮箱" "custodian@gmail.com" validate_email)
password=$(entry "请输入密码" "Administrator" validate_password)

sudo apt update
sudo apt upgrade -y
sudo apt install -y curl nano ufw wget vim dnsutils cpufrequtils unzip python3 python3-pip python3-venv
sudo systemctl enable ssh
sudo systemctl enable sshd

sudo ln -sf /usr/bin/python3 /usr/bin/py
sudo ln -sf /usr/bin/python3 /usr/bin/python

sudo pip3 install --break-system-packages flask
sudo pip3 install --break-system-packages waitress
sudo pip3 install --break-system-packages requests
sudo pip3 install --break-system-packages cryptography

mkdir /opt && cd /opt
curl -O https://github.com/xlinmengen/proxy-assets/releases/download/assets/image.zip
mkdir repo && cd repo
curl -O https://github.com/xlinmengen/proxy-assets/releases/download/assets/Xray-linux-64.zip
curl -O https://github.com/xlinmengen/proxy-assets/releases/download/assets/frp_linux_amd64.zip
curl -O https://github.com/xlinmengen/proxy-assets/releases/download/assets/frp_darwin_amd64.zip
curl -O https://github.com/xlinmengen/proxy-assets/releases/download/assets/frp_windows_amd64.zip
cd ..
unzip -oq image.zip -d /

chmod -R +rw /opt/
chmod +x /opt/xray/xray
chmod +x /opt/frps/frps

uuid=$(cat /proc/sys/kernel/random/uuid | tr -d '\n')
token=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1 | tr -d '\n')
shortid=$(cat /dev/urandom | tr -dc 'A-F0-9' | fold -w 16 | head -n 1 | tr -d '\n')
serverip=$(hostname -I | awk '{print $1}')

parse_xray_keys

sed -i "s/#\[token\]/${token}/g" /opt/frps/frps.toml
sed -i "s/#\[username\]/${email}/g" /opt/frps/frps.toml
sed -i "s/#\[password\]/${password}/g" /opt/frps/frps.toml

sed -i "s/#\[uuid\]/${uuid}/g" /opt/xray/config.json
sed -i "s/#\[email\]/${email}/g" /opt/xray/config.json
sed -i "s/#\[shortid\]/${shortid}/g" /opt/xray/config.json
sed -i "s/#\[privatekey\]/${privatekey}/g" /opt/xray/config.json

sed -i "s/#\[uuid\]/${uuid}/g" /opt/monitor/datas/settings.json
sed -i "s/#\[email\]/${email}/g" /opt/monitor/datas/settings.json
sed -i "s/#\[shortid\]/${shortid}/g" /opt/monitor/datas/settings.json
sed -i "s/#\[serverip\]/${serverip}/g" /opt/monitor/datas/settings.json
sed -i "s/#\[password\]/${password}/g" /opt/monitor/datas/settings.json
sed -i "s/#\[privatekey\]/${privatekey}/g" /opt/monitor/datas/settings.json
sed -i "s/#\[passwordkey\]/${passwordkey}/g" /opt/monitor/datas/settings.json

systemctl restart frps
systemctl enable frps
systemctl restart xray
systemctl enable xray
systemctl restart monitor
systemctl enable monitor

###################################################

cat > /etc/hosts << 'Config_EOF'
127.0.0.1 localhost gate
::1 localhost ip6-localhost ip6-loopback
Config_EOF

cat > /etc/security/limits.conf << 'Config_EOF'
* soft nofile 1024000
* hard nofile 1024000
root soft nofile 1024000
root hard nofile 1024000
Config_EOF

cat > /etc/sysctl.conf << 'Config_EOF'
# /etc/sysctl.conf - 高性能网络优化配置

# ===== 核心 =====
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# ===== 缓冲区 =====
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 87380
net.core.wmem_default = 65536
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_mem = 262144 524288 1572864

# ===== TCP优化 =====
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_rfc1337 = 1

# ===== 连接跟踪 =====
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 86400
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30

# ===== TIME-WAIT =====
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_max_tw_buckets = 2000000

# ===== 端口 =====
net.ipv4.ip_local_port_range = 1024 65535

# ===== 队列 =====
net.core.netdev_max_backlog = 10000
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_syncookies = 1

# ===== Keepalive =====
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 5

# ===== ARP =====
net.ipv4.neigh.default.base_reachable_time_ms = 600000
net.ipv4.neigh.default.retrans_time_ms = 250
net.ipv4.neigh.default.mcast_solicit = 20
net.ipv4.neigh.default.delay_first_probe_time = 1

# ===== 反向路径过滤 =====
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.eth0.rp_filter = 0
net.ipv4.conf.eth1.rp_filter = 0

# ===== ICMP安全 =====
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1

# ===== 其他 =====
net.ipv6.conf.all.disable_ipv6 = 0
kernel.sysrq = 438
Config_EOF

sudo sysctl -p

cat > /etc/default/cpufrequtils << EOF
GOVERNOR="performance"
EOF

systemctl restart cpufrequtils

###################################################

cat > /etc/ssh/sshd_config << 'Config_EOF'
Include /etc/ssh/sshd_config.d/*.conf
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
PermitRootLogin yes
SyslogFacility AUTH
PrintLastLog yes
MaxAuthTries = 3
LogLevel INFO
UseDNS no
Port 22
Config_EOF

sudo systemctl restart systemd-networkd
sudo systemctl restart systemd-resolved
sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

echo && echo "UUID: $uuid" && echo
sudo passwd && echo

sudo systemctl reload ssh
sudo systemctl reload sshd

ufw --force reset
sudo ufw default deny  incoming
sudo ufw default allow outgoing
ufw allow 443/tcp comment 'Xray Proxy Service'
ufw allow 80/tcp comment 'Web Monitor Service'
ufw delete 3
ufw delete 3
echo y|ufw enable
