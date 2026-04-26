#!/bin/bash

RED='\033[0;31m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
FL='\033[1A\r\033[K'
NC='\033[0m'

ICON_PROMPT="🔹"
ICON_ERROR="[FAIL]"

# ========== 解析 xray x25519 输出 ==========
parse_xray_keys() {
    local output
    local private_key=""
    local public_key =""

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
SCRIPT_START=$(date +%s)

sudo hostnamectl set-hostname server
echo 'PS1='\''${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '\' | sudo tee -a ~/.bashrc > /dev/null

sudo apt update
sudo apt upgrade -y
sudo apt install -y curl nano ufw wget vim dnsutils cpufrequtils unzip python3 python3-pip python3-venv
sudo systemctl enable ssh
sudo systemctl enable sshd

sudo ln -sf /usr/bin/python3 /usr/bin/py
sudo ln -sf /usr/bin/python3 /usr/bin/python

sudo pip3 install --break-system-packages flask==3.0.3
sudo pip3 install --break-system-packages grpcio==1.78.0
sudo pip3 install --break-system-packages gevent
sudo pip3 install --break-system-packages urllib3
sudo pip3 install --break-system-packages requests
sudo pip3 install --break-system-packages cryptography
sudo pip3 install --break-system-packages google-api-python-client

sudo mkdir -p /opt/repo ; cd $_
sudo wget https://github.com/xlinmengen/proxy-assets/releases/download/assets/image.zip
sudo wget https://github.com/xlinmengen/proxy-assets/releases/download/assets/Xray-linux-64.zip
sudo wget https://github.com/xlinmengen/proxy-assets/releases/download/assets/frp_linux_amd64.zip
sudo wget https://github.com/xlinmengen/proxy-assets/releases/download/assets/frp_darwin_amd64.zip
sudo wget https://github.com/xlinmengen/proxy-assets/releases/download/assets/frp_windows_amd64.zip
sudo unzip -oq image.zip -d / ; rm -f image.zip

sudo mkdir -p /opt/monitor/datas/custom ; cd $_
sudo wget https://raw.githubusercontent.com/xlinmengen/proxy-assets/main/ruleset/proxy.yaml
sudo wget https://raw.githubusercontent.com/xlinmengen/proxy-assets/main/ruleset/direct.yaml
sudo wget https://raw.githubusercontent.com/xlinmengen/proxy-assets/main/ruleset/reject.yaml

sudo chmod -R +rw /opt/
sudo chmod +x /opt/xray/xray
sudo chmod +x /opt/frps/frps

uuid=$(cat /proc/sys/kernel/random/uuid | tr -d '\n')
token=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1 | tr -d '\n')
shortid=$(cat /dev/urandom | tr -dc 'A-F0-9' | fold -w 16 | head -n 1 | tr -d '\n')
serverip=$(hostname -I | awk '{print $1}')

parse_xray_keys

sudo sed -i "s/#\[token\]/${token}/g" /opt/frps/frps.toml
sudo sed -i "s/#\[username\]/${email}/g" /opt/frps/frps.toml
sudo sed -i "s/#\[password\]/${password}/g" /opt/frps/frps.toml

sudo sed -i "s/#\[uuid\]/${uuid}/g" /opt/xray/config.json
sudo sed -i "s/#\[email\]/${email}/g" /opt/xray/config.json
sudo sed -i "s/#\[shortid\]/${shortid}/g" /opt/xray/config.json
sudo sed -i "s/#\[privatekey\]/${privatekey}/g" /opt/xray/config.json

sudo sed -i "s/#\[uuid\]/${uuid}/g" /opt/monitor/datas/settings.json
sudo sed -i "s/#\[token\]/${token}/g" /opt/monitor/datas/settings.json
sudo sed -i "s/#\[email\]/${email}/g" /opt/monitor/datas/settings.json
sudo sed -i "s/#\[shortid\]/${shortid}/g" /opt/monitor/datas/settings.json
sudo sed -i "s/#\[serverip\]/${serverip}/g" /opt/monitor/datas/settings.json
sudo sed -i "s/#\[password\]/${password}/g" /opt/monitor/datas/settings.json
sudo sed -i "s/#\[privatekey\]/${privatekey}/g" /opt/monitor/datas/settings.json
sudo sed -i "s/#\[passwordkey\]/${passwordkey}/g" /opt/monitor/datas/settings.json

sudo sysctl -p
sudo systemctl daemon-reload
sudo systemctl reload ssh
sudo systemctl reload sshd
sudo systemctl enable --now xray
sudo systemctl enable --now frps
sudo systemctl enable --now monitor
sudo systemctl restart cpufrequtils
sudo systemctl restart systemd-networkd
sudo systemctl restart systemd-resolved
sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

sudo ufw --force reset >/dev/null
sudo ufw default deny  incoming >/dev/null
sudo ufw default allow outgoing >/dev/null
sudo ufw allow 20/tcp   comment 'FRP Service' >/dev/null
sudo ufw allow 80/tcp   comment 'Web Monitor Service' >/dev/null
sudo ufw allow 443/tcp  comment 'Xray Proxy  Service' >/dev/null
sudo ufw allow 5000/tcp comment 'Web Monitor Service' >/dev/null
echo y|sudo -S ufw delete 5 >/dev/null
echo y|sudo -S ufw delete 5 >/dev/null
echo y|sudo -S ufw delete 5 >/dev/null
echo y|sudo -S ufw delete 5 >/dev/null
echo y|sudo -S ufw enable   >/dev/null

###################################################

SCRIPT_END=$(date +%s)
DURATION=$((SCRIPT_END - SCRIPT_START))
MIN=$((DURATION / 60))
SEC=$((DURATION % 60))

echo
echo -e "${CYAN}══════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}                   部署完成，总耗时: ${MIN}m ${SEC}s             ${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════════════════${NC}"
echo
echo -e "${CYAN}    Server Monitor:  ${GREEN}https://${serverip}:5000/${NC}"
echo -e "${CYAN}    Server Assets :  ${GREEN}https://${serverip}:5000/assets${NC}"
echo
echo -e "${CYAN}══════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}    首次访问请手动信任自签名证书${NC}"
echo -e "${YELLOW}    确保防火墙已开放 20/80/443/5000 端口${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════════════════${NC}"
echo
