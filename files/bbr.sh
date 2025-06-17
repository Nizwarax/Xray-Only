#!/bin/bash
function memasang_bbr_hybla(){
  clear
  print_install "Memasang BBR Hybla"
  gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
  gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v${gotop_latest}_linux_amd64.deb"
  curl -sL "$gotop_link" -o /tmp/gotop.deb
  dpkg -i /tmp/gotop.deb >/dev/null 2>&1

  apt install -y ethtool net-tools haveged htop iftop

  systemctl enable haveged
  systemctl start haveged

  echo -e "${YELLOW} Mengoptimasi parameter kernel...${NC}"
  cat > /etc/sysctl.d/99-network-tune.conf << EOF
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 65536
net.core.somaxconn = 32768
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_mem = 65536 131072 262144
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.ip_local_port_range = 1024 65535
vm.swappiness = 10
vm.dirty_ratio = 60
vm.dirty_background_ratio = 2
net.core.busy_poll = 50
net.core.busy_read = 50
EOF

  sysctl -p /etc/sysctl.d/99-network-tune.conf

  echo -e "${YELLOW} Memeriksa dan mengaktifkan BBR congestion control...${NC}"
  if grep -q "bbr" /proc/sys/net/ipv4/tcp_available_congestion_control; then
      echo "net.core.default_qdisc=fq" >> /etc/sysctl.d/99-network-tune.conf
      echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/99-network-tune.conf
      sysctl -p /etc/sysctl.d/99-network-tune.conf
      echo -e "${GREEN} BBR congestion control berhasil diaktifkan${NC}"
  else
      echo -e "${RED} BBR tidak tersedia pada kernel ini${NC}"
  fi

  echo -e "${YELLOW} Mengoptimasi network interfaces...${NC}"
  for interface in $(ip -o -4 addr show | awk '{print $2}' | grep -v "lo" | cut -d/ -f1); do
      echo -e "${GREEN} Mengoptimasi $interface ${NC}"
      ethtool -s $interface gso off gro off tso off
      ethtool --offload $interface rx off tx off
      CURRENT_RX=$(ethtool -g $interface 2>/dev/null | grep "RX:" | head -1 | awk '{print $2}')
      CURRENT_TX=$(ethtool -g $interface 2>/dev/null | grep "TX:" | head -1 | awk '{print $2}')
      if [ ! -z "$CURRENT_RX" ] && [ ! -z "$CURRENT_TX" ]; then
          ethtool -G $interface rx $CURRENT_RX tx $CURRENT_TX
      fi
  done

  echo -e "${YELLOW} Mengkonfigurasi QoS untuk prioritas paket...${NC}"
  cat > /usr/local/sbin/network-tune.sh << 'EOF'
#!/bin/bash
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags ACK ACK -j CLASSIFY --set-class 1:1
iptables -t mangle -A PREROUTING -p tcp -m length --length 0:128 -j CLASSIFY --set-class 1:1
iptables -t mangle -A PREROUTING -p udp -m length --length 0:128 -j CLASSIFY --set-class 1:1
iptables -t mangle -A PREROUTING -p icmp -j CLASSIFY --set-class 1:1
INTERFACES=$(ip -o -4 addr show | awk '{print $2}' | grep -v "lo" | cut -d/ -f1)
for IFACE in $INTERFACES; do
    tc qdisc del dev $IFACE root 2> /dev/null
    tc qdisc add dev $IFACE root handle 1: htb default 10
    tc class add dev $IFACE parent 1: classid 1:1 htb rate 1000mbit ceil 1000mbit prio 1
    tc qdisc add dev $IFACE parent 1:1 fq_codel quantum 300 ecn
done
EOF

  chmod +x /usr/local/sbin/network-tune.sh
  /usr/local/sbin/network-tune.sh

  echo -e "${YELLOW} Membuat systemd service...${NC}"
  cat > /etc/systemd/system/network-tune.service << EOF
[Unit]
Description=Network Optimization for Low Latency
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/network-tune.sh
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable network-tune.service
  systemctl start network-tune.service

  total_ram=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
  if [ "$total_ram" -le 4096 ]; then
    echo -e "${YELLOW}RAM terdeteksi ${total_ram}MB. Mengaktifkan swap 2GB untuk kestabilan sistem.${NC}"
    SWAP_SIZE_MB=2048

    if swapon --show | grep -q "/swapfile"; then
      echo -e "${RED}Swapfile sudah aktif, lewati pembuatan swap.${NC}"
    else
      echo -e "${CYAN}Membuat swap file sebesar ${SWAP_SIZE_MB}MB...${NC}"

      if command -v fallocate >/dev/null && fallocate -l "${SWAP_SIZE_MB}M" /swapfile; then
        echo -e "${GREEN}Berhasil menggunakan fallocate.${NC}"
      else
        echo -e "${YELLOW}fallocate gagal, menggunakan dd...${NC}"
        dd if=/dev/zero of=/swapfile bs=1M count=$SWAP_SIZE_MB status=progress
      fi

      chmod 600 /swapfile
      mkswap /swapfile
      swapon /swapfile
      chown root:root /swapfile

      if ! grep -q "/swapfile" /etc/fstab; then
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
        echo -e "${GREEN}Swap ditambahkan ke /etc/fstab${NC}"
      fi

      sysctl -w vm.swappiness=10 >/dev/null
      sysctl -w vm.vfs_cache_pressure=50 >/dev/null
      sed -i '/vm.swappiness/d' /etc/sysctl.conf
      sed -i '/vm.vfs_cache_pressure/d' /etc/sysctl.conf
      echo "vm.swappiness=10" >> /etc/sysctl.conf
      echo "vm.vfs_cache_pressure=50" >> /etc/sysctl.conf
      sysctl -p >/dev/null
    fi
  else
    echo -e "${GREEN}RAM ${total_ram}MB terdeteksi cukup besar. Melewati pembuatan swap.${NC}"
  fi

  clear
  print_success "BBR Hybla selesai dipasang!"
}
