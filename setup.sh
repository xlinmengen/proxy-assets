#!/bin/bash
sudo hostnamectl set-hostname server

echo "PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '" >>~/.bashrc

sudo apt update
sudo apt upgrade -y
sudo apt install -y curl nano ufw wget vim dnsutils cpufrequtils unzip
sudo systemctl enable ssh
sudo systemctl enable sshd

ufw --force reset
sudo ufw default deny  incoming
sudo ufw default allow outgoing
ufw allow 443/tcp comment 'Xray Proxy Service'
ufw allow 80/tcp comment 'Web Monitor Service'
ufw delete 3
ufw delete 3
echo y|ufw enable



uuid=$(cat /proc/sys/kernel/random/uuid | tr -d '\n')
echo $uuid >uuid.key

systemctl restart xray
systemctl enable xray

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
Port 37201
UseDNS no
Config_EOF

sudo systemctl restart systemd-networkd
sudo systemctl restart systemd-resolved
sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

echo && echo "UUID: $uuid" && echo
sudo passwd && echo

sudo systemctl reload ssh
sudo systemctl reload sshd