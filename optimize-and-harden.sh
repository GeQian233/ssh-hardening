#!/usr/bin/env bash
# 完整一键优化 + SSH 加固脚本
# 流程：系统升级 → 启用 BBR → TCP 窗口调优 → 调用原有 SSH 加固脚本
# 仅支持 Ubuntu 24.04+ / Debian 12+
# 作者仓库：https://github.com/GeQian233/ssh-hardening

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

# 加载模块
if ! lsmod | grep -q '^tcp_bbr'; then
  modprobe tcp_bbr 2>/dev/null || warn "modprobe tcp_bbr 失败（某些内核可能已内置）"
fi

# 持久化模块加载
mkdir -p /etc/modules-load.d
echo 'tcp_bbr' > /etc/modules-load.d/bbr.conf
chmod 644 /etc/modules-load.d/bbr.conf

# 使用独立 drop-in，避免污染主 sysctl.conf
cat > /etc/sysctl.d/99-bbr.conf <<'EOF'
# Managed by optimize-and-harden.sh
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
chmod 644 /etc/sysctl.d/99-bbr.conf

sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-bbr.conf >/dev/null 2>&1 || true

# 验证
CURRENT_CC="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
AVAILABLE_CC="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo unknown)"
info "当前拥塞控制：${CURRENT_CC}"
info "可用算法：${AVAILABLE_CC}"
if [[ "$CURRENT_CC" == "bbr" ]]; then
  info "BBR 已成功启用。"
else
  warn "BBR 可能未完全生效，请检查内核是否支持（需要 4.9+）。"
fi

# ---------- 3. TCP 窗口与网络调优 ----------
step "3. TCP 窗口调优（等效于常见 tools.sh 参数）"

cat > /etc/sysctl.d/99-tcp-tune.conf <<'EOF'
# Managed by optimize-and-harden.sh
# TCP 窗口与缓冲区调优（保守且常用的高性能参数）
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_ecn=0
net.ipv4.tcp_frto=0
net.ipv4.tcp_mtu_probing=0
net.ipv4.tcp_rfc1337=0
net.ipv4.tcp_sack=1
net.ipv4.tcp_fack=1
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_adv_win_scale=1
net.ipv4.tcp_moderate_rcvbuf=1
net.core.rmem_max=33554432
net.core.wmem_max=33554432
net.ipv4.tcp_rmem=4096 87380 33554432
net.ipv4.tcp_wmem=4096 16384 33554432
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
net.ipv4.tcp_slow_start_after_idle=0
fs.file-max=1000000
EOF
chmod 644 /etc/sysctl.d/99-tcp-tune.conf

sysctl --system >/dev/null 2>&1 || true
info "TCP 调优参数已写入 /etc/sysctl.d/99-tcp-tune.conf 并应用。"

# ---------- 4. 其他实用优化 ----------
step "4. 其他补充优化"

# 提高文件描述符限制（systemd 层面）
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
