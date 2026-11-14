#!/usr/bin/env bash
# 完整一键优化 + SSH 加固脚本
# 流程：系统升级 → 启用 BBR → TCP 基础调优（动态 BDP 缓冲区 + initcwnd） → 调用原有 SSH 加固脚本
# 仅支持 Ubuntu 24.04+ / Debian 12+
# 作者仓库：https://github.com/GeQian233/ssh-hardening
# TCP 基础调优思路参考 tcpfit（Kylin010/tcpfit），仅实现基础部分，不含拐点扫描与整形

set -Eeuo pipefail
umask 077

# 颜色
if [[ -t 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
fi

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
step()  { echo -e "\n${BLUE}========== $* ==========${NC}"; }

# 必须 root
[[ ${EUID:-$(id -u)} -eq 0 ]] || { err "请使用 root 运行：sudo bash $0"; exit 1; }

# 交互终端检查
if [[ ! -r /dev/tty || ! -w /dev/tty ]]; then
  err "未检测到可用交互式终端（/dev/tty）。请在分配了 PTY 的 SSH 会话中运行。"
  exit 1
fi

# ---------- 1. 系统识别与升级 ----------
step "1. 系统识别与软件包升级"

[[ -r /etc/os-release ]] || { err "无法读取 /etc/os-release"; exit 1; }
. /etc/os-release

case "${ID:-}" in
  ubuntu)
    dpkg --compare-versions "${VERSION_ID:-0}" ge 24.04 || { err "最低支持 Ubuntu 24.04，当前：${PRETTY_NAME:-unknown}"; exit 1; }
    ;;
  debian)
    dpkg --compare-versions "${VERSION_ID:-0}" ge 12 || { err "最低支持 Debian 12，当前：${PRETTY_NAME:-unknown}"; exit 1; }
    ;;
  *)
    err "仅支持 Ubuntu 24.04+ / Debian 12+，当前：${PRETTY_NAME:-unknown}"
    exit 1
    ;;
esac

info "检测到系统：${PRETTY_NAME:-unknown}"

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export APT_LISTCHANGES_FRONTEND=none

info "正在执行 apt update..."
apt-get update || { err "apt update 失败，请检查网络和软件源"; exit 1; }

warn "即将执行 apt upgrade（可能升级内核等组件，耗时较长，完成后可能需要重启才能完全生效）。"
info "正在执行 apt upgrade..."
if ! apt-get upgrade -y \
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confold" \
    -o APT::Get::Assume-Yes=true; then
  err "apt upgrade 失败，请检查输出后重试。"
  exit 1
fi

info "软件包升级完成。"

# ---------- 2. 启用 BBR ----------
step "2. 启用 TCP BBR"

if ! lsmod | grep -q '^tcp_bbr'; then
  modprobe tcp_bbr 2>/dev/null || warn "modprobe tcp_bbr 失败（某些内核可能已内置）"
fi

mkdir -p /etc/modules-load.d
echo 'tcp_bbr' > /etc/modules-load.d/bbr.conf
chmod 644 /etc/modules-load.d/bbr.conf

cat > /etc/sysctl.d/99-bbr.conf <<'EOF'
# Managed by optimize-and-harden.sh
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
chmod 644 /etc/sysctl.d/99-bbr.conf

sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-bbr.conf >/dev/null 2>&1 || true

CURRENT_CC="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
AVAILABLE_CC="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo unknown)"
info "当前拥塞控制：${CURRENT_CC}"
info "可用算法：${AVAILABLE_CC}"
if [[ "$CURRENT_CC" == "bbr" ]]; then
  info "BBR 已成功启用。"
else
  warn "BBR 可能未完全生效，请检查内核是否支持（需要 4.9+）。"
fi

# ---------- 3. TCP 基础调优（动态 BDP + initcwnd） ----------
step "3. TCP 基础调优（动态缓冲区 + initcwnd）"

# 检测内存
RAM_MB=$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo)
info "检测到内存：${RAM_MB} MB"

# 交互获取带宽与 RTT（用于 BDP 计算）
echo -e "${YELLOW}请输入机器标称带宽（Mbps，例如 500、1000）：${NC}"
read -r -p "> " BW_MBPS || BW_MBPS=500
[[ "$BW_MBPS" =~ ^[0-9]+$ ]] && [[ "$BW_MBPS" -gt 0 ]] || BW_MBPS=500
info "使用带宽：${BW_MBPS} Mbps"

echo -e "${YELLOW}请输入典型 RTT（毫秒，回车默认 150，适合跨境）：${NC}"
read -r -p "> " RTT_MS || RTT_MS=150
[[ "$RTT_MS" =~ ^[0-9]+$ ]] && [[ "$RTT_MS" -ge 1 && "$RTT_MS" -le 500 ]] || RTT_MS=150
info "使用 RTT：${RTT_MS} ms"

# 角色：代理场景保守一点
ROLE="proxy"
info "默认按代理（proxy）角色设置缓冲区（更保守）"

# 计算 BDP（字节）
BDP_BYTES=$(awk -v b="$BW_MBPS" -v r="$RTT_MS" 'BEGIN{printf "%d", b*1000000/8*(r/1000)}')

# 缓冲区上限：2×BDP + 2MiB，受内存约束，下限 4MB，上限 256MB
BUF_MAX=$(awk -v b="$BDP_BYTES" -v m="$RAM_MB" 'BEGIN{
  v = b*2 + 2097152
  cap = m*32768
  if(cap > 268435456) cap = 268435456
  if(v > cap) v = cap
  if(v < 4194304) v = 4194304
  printf "%d", v
}')

# 默认缓冲区（proxy 角色 1MB 起步）
BUF_DEF=1048576

# tcp_mem（页）
TCP_MEM=$(awk -v m="$RAM_MB" 'BEGIN{
  pg=m*1024/4
  low=int(pg/16); pres=int(pg/8); max=int(pg/4)
  if(low<4096) low=4096; if(pres<8192) pres=8192; if(max<16384) max=16384
  printf "%d %d %d", low, pres, max
}')

info "BDP ≈ $((BDP_BYTES/1048576)) MB，缓冲区上限 ≈ $((BUF_MAX/1048576)) MB"

# 写入完整调优配置
cat > /etc/sysctl.d/99-tcp-tune.conf <<EOF
# Managed by optimize-and-harden.sh
# 基础调优：动态 BDP 缓冲区 + 常用优化参数
# 带宽 ${BW_MBPS} Mbps / RTT ${RTT_MS} ms / RAM ${RAM_MB} MB / role ${ROLE}

# 拥塞控制与队列
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

# 缓冲区（动态计算）
net.core.rmem_max=${BUF_MAX}
net.core.wmem_max=${BUF_MAX}
net.ipv4.tcp_rmem=4096 ${BUF_DEF} ${BUF_MAX}
net.ipv4.tcp_wmem=4096 ${BUF_DEF} ${BUF_MAX}
net.ipv4.tcp_mem=${TCP_MEM}

# 窗口与基础优化
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_moderate_rcvbuf=1
net.ipv4.tcp_adv_win_scale=1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_sack=1
net.ipv4.tcp_dsack=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_fastopen=3

# 队列与连接
net.core.netdev_max_backlog=16384
net.core.netdev_budget=600
net.core.optmem_max=65536
net.core.somaxconn=8192
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_keepalive_time=600
net.ipv4.ip_local_port_range=1024 65535

# 其他
vm.min_free_kbytes=32768
fs.file-max=1000000
EOF
chmod 644 /etc/sysctl.d/99-tcp-tune.conf

sysctl --system >/dev/null 2>&1 || true
info "TCP 基础调优参数已写入 /etc/sysctl.d/99-tcp-tune.conf 并应用。"

# 设置 initcwnd / initrwnd = 32 并尝试简单持久化
step "3.1 设置 initcwnd=32"

if ip route show default >/dev/null 2>&1; then
  DEFAULT_ROUTE=$(ip route show default | head -1)
  if [[ -n "$DEFAULT_ROUTE" ]]; then
    ip route replace $DEFAULT_ROUTE initcwnd 32 initrwnd 32 2>/dev/null && \
      info "已为默认路由设置 initcwnd/initrwnd=32" || \
      warn "设置 initcwnd 失败（可能需要手动处理）"
  fi
fi

# 简单持久化：systemd oneshot（重启后重新应用）
mkdir -p /usr/local/sbin
cat > /usr/local/sbin/set-initcwnd.sh <<'EOF'
#!/bin/bash
# 简单恢复 initcwnd=32
sleep 2
ip route show default | head -1 | while read -r line; do
  ip route replace $line initcwnd 32 initrwnd 32 2>/dev/null || true
done
EOF
chmod 755 /usr/local/sbin/set-initcwnd.sh

cat > /etc/systemd/system/set-initcwnd.service <<'EOF'
[Unit]
Description=Restore initcwnd=32 on default route
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/set-initcwnd.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable --now set-initcwnd.service >/dev/null 2>&1 || warn "initcwnd 服务启用失败（可忽略）"
info "已创建简单 initcwnd 持久化服务（重启后生效）"

# ---------- 4. 其他实用优化 ----------
step "4. 其他补充优化"

mkdir -p /etc/systemd/system.conf.d
cat > /etc/systemd/system.conf.d/limits.conf <<'EOF'
[Manager]
DefaultLimitNOFILE=1048576
DefaultLimitNPROC=1048576
EOF
systemctl daemon-reload >/dev/null 2>&1 || true

info "已提高 systemd 默认文件描述符限制。"

# ---------- 5. 调用原有 SSH 加固脚本 ----------
step "5. 执行 SSH 安全加固（调用仓库原有脚本）"

REPO='GeQian233/ssh-hardening'
BRANCH='main'
HARDEN_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/ssh-hardening.sh"
TMP_HARDEN="$(mktemp /tmp/ssh-hardening.XXXXXX.sh)"

cleanup() { rm -f "$TMP_HARDEN"; }
trap cleanup EXIT

info "正在下载原有 SSH 加固脚本..."
if command -v curl >/dev/null 2>&1; then
  curl -fLsS --retry 3 --connect-timeout 15 "$HARDEN_URL" -o "$TMP_HARDEN" || { err "下载失败"; exit 1; }
elif command -v wget >/dev/null 2>&1; then
  wget -q --timeout=15 -O "$TMP_HARDEN" "$HARDEN_URL" || { err "下载失败"; exit 1; }
else
  err "缺少 curl 或 wget"
  exit 1
fi

[[ -s "$TMP_HARDEN" ]] || { err "下载文件为空"; exit 1; }
head -n1 "$TMP_HARDEN" | grep -qE '^#!/usr/bin/env bash' || { err "脚本格式不正确"; exit 1; }
bash -n "$TMP_HARDEN" || { err "语法检查失败"; exit 1; }

info "下载及检查通过，开始执行 SSH 加固（需要交互输入端口和公钥）..."
warn "请确保云厂商安全组已放行即将使用的新 SSH 端口。"
warn "执行期间请保持当前 SSH 会话，新端口登录成功前不要关闭。"

# 使用真实终端执行，保证交互正常
exec bash "$TMP_HARDEN" < /dev/tty
