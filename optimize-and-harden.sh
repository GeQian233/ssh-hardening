#!/usr/bin/env bash
# 完整一键优化 + SSH 加固脚本
# 流程：系统升级 → 启用 BBR → TCP 基础调优（动态 BDP 缓冲区 + initcwnd） → 调用原有 SSH 加固脚本
# 支持：Ubuntu 22.04+ / Debian 12+
# 作者仓库：https://github.com/GeQian233/ssh-hardening
# TCP 基础调优思路参考 tcpfit（Kylin010/tcpfit），仅实现基础部分，不含拐点扫描与整形
#
# v3 修复与兼容性：
#   - 版本门槛放宽至 Ubuntu 22.04 / Debian 12，并校验 apt 是否支持 DPkg::Lock::Timeout
#   - grub-pc/install_devices：沿 sysfs 向上遍历物理磁盘，兼容普通分区 / LVM / NVMe，
#     拒绝 dm-*/mapper 等虚拟设备；已有正确值不覆写；探测失败直接跳过，绝不猜测
#   - apt/dpkg 锁：fuser（或 pgrep 兜底）等待 + DPkg::Lock::Timeout，避免与
#     unattended-upgrades 冲突
#   - 升级前预检 dpkg --audit 并尝试自动修复半配置包
#   - sysctl：按 /proc/sys 实际存在的键过滤配置，逐键应用，跨内核版本不再因单个
#     不支持的键导致整份配置失效；BBR 不可用时自动降级为仅启用 fq
#   - initcwnd/initrwnd 不支持时自动降级为只设置 initcwnd
#   - 新增 --skip-upgrade：apt 出问题时仍可继续后续加固
#   - 交互输入从 /dev/tty 读取；vm.min_free_kbytes 按内存自适应；显式 chmod 644
#   - 末尾去掉 exec，保证 EXIT trap 清理所有临时文件
#
# 用法：
#   sudo bash optimize-and-harden.sh
#   sudo bash optimize-and-harden.sh --skip-upgrade
#   sudo bash optimize-and-harden.sh --help

set -Eeuo pipefail
umask 077

# ---------- 输出 ----------
if [[ -t 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
fi

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
step()  { echo -e "\n${BLUE}========== $* ==========${NC}"; }

# ---------- 参数 ----------
SKIP_UPGRADE=0
case "${1:-}" in
  --skip-upgrade) SKIP_UPGRADE=1 ;;
  -h|--help)
    echo "用法: sudo bash $0 [--skip-upgrade]"
    echo "  --skip-upgrade  跳过 apt update/upgrade，直接执行 BBR / TCP 调优 / SSH 加固"
    exit 0 ;;
  "") : ;;
  *)  err "未知参数：${1}"; exit 2 ;;
esac

# ---------- 运行环境 ----------
[[ ${EUID:-$(id -u)} -eq 0 ]] || { err "请使用 root 运行：sudo bash $0"; exit 1; }

if [[ ! -r /dev/tty || ! -w /dev/tty ]]; then
  err "未检测到可用交互式终端（/dev/tty）。请在分配了 PTY 的 SSH 会话中运行。"
  exit 1
fi

# ---------- 临时文件统一清理 ----------
TMP_FILES=()
cleanup() {
  local f
  for f in "${TMP_FILES[@]}"; do
    if [[ -n "$f" ]]; then rm -f "$f" || true; fi
  done
  if [[ -n "${TMP_HARDEN:-}" ]]; then rm -f "$TMP_HARDEN" || true; fi
}
trap cleanup EXIT

# ---------- 工具依赖检查 ----------
MISSING=0
for tool in awk dpkg apt-get mktemp; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    err "缺少必要命令：$tool（最小化镜像请先安装对应软件包）"
    MISSING=1
  fi
done
for tool in findmnt lsblk systemctl fuser pgrep ip sysctl debconf-show debconf-set-selections; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    warn "未找到 $tool，相关步骤将自动降级或跳过"
  fi
done
if (( MISSING != 0 )); then exit 1; fi

# ---------- 公共函数 ----------

# 判断 apt 是否支持 DPkg::Lock::Timeout（apt >= 2.0；22.04 / Debian 12 均支持）
APT_LOCK_TIMEOUT_SUPPORTED=0
apt_supports_lock_timeout() {
  local v major
  v=$(dpkg-query -W -f='${Version}' apt 2>/dev/null || true)
  major=${v%%.*}
  if [[ "$major" =~ ^[0-9]+$ ]] && (( major >= 2 )); then
    APT_LOCK_TIMEOUT_SUPPORTED=1
  fi
}

# 等待其他 apt/dpkg 操作结束（fuser 不可用时用 pgrep 兜底）
wait_apt_locks() {
  local i=0 busy
  while true; do
    busy=0
    if command -v fuser >/dev/null 2>&1; then
      if fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock \
               /var/cache/apt/archives/lock /var/lib/apt/lists/lock \
               >/dev/null 2>&1; then
        busy=1
      fi
    elif command -v pgrep >/dev/null 2>&1; then
      # comm 会被内核截断到 15 字符：unattended-upgrade -> unattended-upgr
      if pgrep -x 'apt-get|apt|dpkg|dpkg-deb|unattended-upgr' >/dev/null 2>&1; then
        busy=1
      fi
    fi
    if (( busy == 0 )); then return 0; fi

    i=$(( i + 1 ))
    if (( i % 20 == 0 )); then
      warn "等待 apt/dpkg 锁释放（已等待 $(( i * 3 )) 秒）..."
    fi
    if (( i > 200 )); then
      err "等待 apt 锁超时（10 分钟）。请稍后重试，或加 --skip-upgrade 跳过升级"
      return 1
    fi
    sleep 3
  done
}

# 列出真实物理磁盘（排除 dm/loop/sr/ram/zram/md 等虚拟设备）
list_physical_disks() {
  local d n
  for d in /sys/block/*; do
    n=$(basename "$d")
    case "$n" in
      dm-*|loop*|sr*|ram*|zram*|md*) continue ;;
    esac
    echo "/dev/$n"
  done
}

# 从根文件系统设备出发，沿 sysfs 向上找到真正的物理磁盘
# 覆盖：普通分区 (/dev/vda2)、LVM (/dev/mapper/vg-lv)、NVMe (nvme0n1p2)、整盘直挂
detect_physical_disk() {
  local src dev parent real guard=0
  command -v findmnt >/dev/null 2>&1 || return 1
  src=$(findmnt -n -o SOURCE / 2>/dev/null || true)
  if [[ -z "$src" ]]; then return 1; fi
  # ZFS / btrfs 子卷等可能给出非 /dev 路径，无法解析则放弃
  if [[ "$src" != /* ]]; then return 1; fi
  dev=$(basename "$(readlink -f "$src")")
  while (( guard++ < 12 )); do
    if [[ -d "/sys/block/$dev" ]]; then
      case "$dev" in
        dm-*|loop*|sr*|ram*|zram*|md*) : ;;   # 虚拟设备，继续向上
        *) echo "/dev/$dev"; return 0 ;;
      esac
    fi
    # 向上走：优先 slaves（dm/md/LVM），否则取 sysfs 路径的上一级（分区）
    parent=$(ls "/sys/class/block/$dev/slaves" 2>/dev/null | head -n1 || true)
    if [[ -z "$parent" ]]; then
      real=$(readlink -f "/sys/class/block/$dev" 2>/dev/null)
      if [[ -z "$real" ]]; then return 1; fi
      parent=$(basename "$(dirname "$real")")
      if [[ -z "$parent" || "$parent" == "block" ]]; then return 1; fi
    fi
    dev=$parent
  done
  return 1
}

# 修正 grub-pc/install_devices
# 原则：探测不到就跳过，绝不猜测；已有正确值就不动
fix_grub_pc_devices() {
  if ! dpkg -s grub-pc >/dev/null 2>&1; then
    info "未安装 grub-pc（UEFI 或其他引导器），跳过安装设备检测。"
    return 0
  fi
  if ! command -v debconf-show >/dev/null 2>&1 \
     || ! command -v debconf-set-selections >/dev/null 2>&1; then
    warn "缺少 debconf 工具，跳过 grub-pc 修正（不影响升级，除非 grub-pc 需重配）"
    return 0
  fi

  local disk cur
  disk=$(detect_physical_disk || true)
  if [[ -z "$disk" || ! -b "$disk" || "$disk" == *mapper* ]]; then
    warn "无法确定物理磁盘，跳过 grub-pc 自动修正（不猜测，避免写错设备）"
    warn "当前可用磁盘：$(list_physical_disks | tr '\n' ' ')"
    return 0
  fi

  # debconf-show 的行首可能是 "* " 或空格，两种格式都兼容
  cur=$(debconf-show grub-pc 2>/dev/null \
        | sed -n 's/^[[:space:]]*\*\{0,1\}[[:space:]]*grub-pc\/install_devices:[[:space:]]*//p' \
        || true)
  if [[ "$cur" == *"$disk"* && "$cur" != *mapper* && "$cur" != *dm-* ]]; then
    info "grub-pc/install_devices 已正确（$cur），无需修改。"
    return 0
  fi

  info "将 grub-pc/install_devices 设为 $disk（原值：${cur:-空}）"
  printf 'grub-pc grub-pc/install_devices multiselect %s\n' "$disk" \
    | debconf-set-selections 2>/dev/null || true
  if command -v debconf-communicate >/dev/null 2>&1; then
    printf 'set grub-pc/install_devices %s\n' "$disk" \
      | debconf-communicate >/dev/null 2>&1 || true
  fi
}

# 升级前预检：修复上一次中断留下的半配置包
repair_dpkg_if_needed() {
  local audit
  audit=$(dpkg --audit 2>&1 || true)
  if [[ -z "$audit" ]]; then return 0; fi

  warn "检测到未完成的 dpkg 事务，先尝试自动修复："
  # 用 sed 读取全部输入，避免 head 提前退出导致 pipefail 下 echo 收到 SIGPIPE
  echo "$audit" | sed -n '1,10p' | sed 's/^/    /'
  # grub-pc 是最常见的失败源，先确保它的配置正确
  fix_grub_pc_devices
  if ! DEBIAN_FRONTEND=noninteractive dpkg --configure -a; then
    err "dpkg --configure -a 失败。请手动修复后重跑，或加 --skip-upgrade 跳过升级。"
    return 1
  fi
  info "dpkg 事务已修复。"
}

# 过滤掉当前内核不提供的 sysctl 键，避免单个不兼容键影响整份配置
filter_sysctl_conf() {
  local src="$1" dst="$2" line key path
  : > "$dst"
  while IFS= read -r line; do
    case "$line" in
      ''|'#'*) printf '%s\n' "$line" >> "$dst"; continue ;;
    esac
    key=${line%%=*}
    key=${key//[[:space:]]/}
    path="/proc/sys/${key//./\/}"
    if [[ -e "$path" ]]; then
      printf '%s\n' "$line" >> "$dst"
    else
      warn "内核未提供 $key，已从配置中剔除"
    fi
  done < "$src"
  chmod 644 "$dst"
}

# 逐键应用 sysctl，单个键被内核拒绝不影响其余参数
apply_sysctl_conf() {
  local file="$1" line k v
  if ! command -v sysctl >/dev/null 2>&1; then
    warn "缺少 sysctl，跳过即时应用（配置已写入，重启后由 systemd-sysctl 生效）"
    return 0
  fi
  while IFS= read -r line; do
    case "$line" in ''|'#'*) continue ;; esac
    k=${line%%=*}
    v=${line#*=}
    k=${k//[[:space:]]/}
    v=$(printf '%s' "$v" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    if [[ -z "$k" || -z "$v" ]]; then continue; fi
    if ! sysctl -w "$k=$v" >/dev/null 2>&1; then
      warn "参数 $k 未被内核接受，已跳过"
    fi
  done < "$file"
}

# ---------- 1. 系统识别与升级 ----------
step "1. 系统识别与软件包升级"

[[ -r /etc/os-release ]] || { err "无法读取 /etc/os-release"; exit 1; }
# shellcheck disable=SC1091
. /etc/os-release

case "${ID:-}" in
  ubuntu)
    dpkg --compare-versions "${VERSION_ID:-0}" ge 22.04 || {
      err "最低支持 Ubuntu 22.04，当前：${PRETTY_NAME:-unknown}"; exit 1; }
    ;;
  debian)
    dpkg --compare-versions "${VERSION_ID:-0}" ge 12 || {
      err "最低支持 Debian 12，当前：${PRETTY_NAME:-unknown}"; exit 1; }
    ;;
  *)
    err "仅支持 Ubuntu 22.04+ / Debian 12+，当前：${PRETTY_NAME:-unknown}"
    exit 1
    ;;
esac

info "检测到系统：${PRETTY_NAME:-unknown}"

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export APT_LISTCHANGES_FRONTEND=none

apt_supports_lock_timeout
if (( APT_LOCK_TIMEOUT_SUPPORTED == 0 )); then
  warn "无法确认 apt 支持 DPkg::Lock::Timeout，将依赖进程级锁等待"
fi

# 无论是否升级，都先修正 grub-pc 配置（写错会阻塞后续所有 apt 操作）
fix_grub_pc_devices

if (( SKIP_UPGRADE == 1 )); then
  warn "已指定 --skip-upgrade：跳过 apt update / apt upgrade。"
else
  wait_apt_locks || exit 1
  repair_dpkg_if_needed || exit 1

  APT_OPTS=()
  if (( APT_LOCK_TIMEOUT_SUPPORTED == 1 )); then
    APT_OPTS=(-o DPkg::Lock::Timeout=600)
  fi

  info "正在执行 apt update..."
  if ! apt-get "${APT_OPTS[@]}" update; then
    err "apt update 失败，请检查网络和软件源。"
    err "注意：BBR / TCP 调优 / SSH 加固均未执行，请先修复后重跑本脚本。"
    exit 1
  fi

  warn "即将执行 apt upgrade（可能升级内核等组件，耗时较长，完成后可能需要重启才能完全生效）。"
  info "正在执行 apt upgrade..."
  wait_apt_locks || exit 1
  if ! apt-get "${APT_OPTS[@]}" upgrade -y \
      -o Dpkg::Options::="--force-confdef" \
      -o Dpkg::Options::="--force-confold"; then
    err "apt upgrade 失败，请检查输出后重试。"
    err "注意：BBR / TCP 调优 / SSH 加固均未执行，请先修复后重跑本脚本。"
    err "若只是 apt 出问题但想继续加固，可使用：sudo bash $0 --skip-upgrade"
    exit 1
  fi

  info "软件包升级完成。"
fi

# ---------- 2. 启用 BBR ----------
step "2. 启用 TCP BBR"

# 用 /proc/modules 判断，避免 lsmod | grep -q 在 pipefail 下因 SIGPIPE 误判
BBR_AVAILABLE=0
if ! grep -q '^tcp_bbr ' /proc/modules 2>/dev/null; then
  modprobe tcp_bbr 2>/dev/null || true
fi
if grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
  BBR_AVAILABLE=1
fi

mkdir -p /etc/modules-load.d
if (( BBR_AVAILABLE == 1 )); then
  echo 'tcp_bbr' > /etc/modules-load.d/bbr.conf
else
  : > /etc/modules-load.d/bbr.conf
  warn "当前内核不支持 BBR，跳过模块加载与拥塞控制设置"
fi
chmod 644 /etc/modules-load.d/bbr.conf

mkdir -p /etc/sysctl.d
BBR_CONF=/etc/sysctl.d/99-bbr.conf
if (( BBR_AVAILABLE == 1 )); then
  cat > "$BBR_CONF" <<'EOF'
# Managed by optimize-and-harden.sh
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
else
  cat > "$BBR_CONF" <<'EOF'
# Managed by optimize-and-harden.sh
# 当前内核不支持 BBR，仅启用 fq 队列管理
net.core.default_qdisc=fq
EOF
fi
chmod 644 "$BBR_CONF"

# 先整体验证，再逐键兜底应用，确保跨内核版本都能生效
sysctl --system >/dev/null 2>&1 || true
apply_sysctl_conf "$BBR_CONF"

CURRENT_CC="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
AVAILABLE_CC="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo unknown)"
info "当前拥塞控制：${CURRENT_CC}"
info "可用算法：${AVAILABLE_CC}"
if [[ "$CURRENT_CC" == "bbr" ]]; then
  info "BBR 已成功启用。"
elif (( BBR_AVAILABLE == 1 )); then
  warn "BBR 可能未完全生效，请检查内核是否支持（需要 4.9+）。"
fi

# ---------- 3. TCP 基础调优（动态 BDP + initcwnd） ----------
step "3. TCP 基础调优（动态缓冲区 + initcwnd）"

RAM_MB=$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo)
info "检测到内存：${RAM_MB} MB"

# 交互获取带宽与 RTT，显式从 /dev/tty 读取
echo -e "${YELLOW}请输入机器标称带宽（Mbps，例如 500、1000）：${NC}"
read -r -p "> " BW_MBPS < /dev/tty || BW_MBPS=500
if [[ "$BW_MBPS" =~ ^[0-9]+$ ]] && (( BW_MBPS > 0 )); then :; else BW_MBPS=500; fi
info "使用带宽：${BW_MBPS} Mbps"

echo -e "${YELLOW}请输入典型 RTT（毫秒，回车默认 150，适合跨境）：${NC}"
read -r -p "> " RTT_MS < /dev/tty || RTT_MS=150
if [[ "$RTT_MS" =~ ^[0-9]+$ ]] && (( RTT_MS >= 1 && RTT_MS <= 500 )); then :; else RTT_MS=150; fi
info "使用 RTT：${RTT_MS} ms"

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

BUF_DEF=1048576

# tcp_mem（页）
TCP_MEM=$(awk -v m="$RAM_MB" 'BEGIN{
  pg=m*1024/4
  low=int(pg/16); pres=int(pg/8); max=int(pg/4)
  if(low<4096) low=4096; if(pres<8192) pres=8192; if(max<16384) max=16384
  printf "%d %d %d", low, pres, max
}')

# min_free_kbytes 按内存自适应：约 1%，下限 16MB、上限 64MB
# 固定 32768 在 1GB 小内存 VPS 上偏高，会加剧 kswapd 回收
MIN_FREE=$(( RAM_MB * 1024 / 100 ))
if (( MIN_FREE < 16384 )); then MIN_FREE=16384; fi
if (( MIN_FREE > 65536 )); then MIN_FREE=65536; fi

info "BDP ≈ $((BDP_BYTES/1048576)) MB，缓冲区上限 ≈ $((BUF_MAX/1048576)) MB，min_free_kbytes=${MIN_FREE}"

# 先写完整参考配置，再按当前内核实际提供的键过滤
TUNE_TMP=$(mktemp /tmp/99-tcp-tune.XXXXXX.conf)
TMP_FILES+=("$TUNE_TMP")
cat > "$TUNE_TMP" <<EOF
# 基础调优：动态 BDP 缓冲区 + 常用优化参数
# 带宽 ${BW_MBPS} Mbps / RTT ${RTT_MS} ms / RAM ${RAM_MB} MB / role ${ROLE}
# 由 optimize-and-harden.sh 生成；不存在的内核参数已被过滤

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
vm.min_free_kbytes=${MIN_FREE}
fs.file-max=1000000
EOF

# BBR 不可用时移除拥塞控制行，避免 sysctl 报错
TUNE_CONF=/etc/sysctl.d/99-tcp-tune.conf
if (( BBR_AVAILABLE == 0 )); then
  sed -i '/^net\.ipv4\.tcp_congestion_control=bbr$/d' "$TUNE_TMP"
fi
filter_sysctl_conf "$TUNE_TMP" "$TUNE_CONF"
apply_sysctl_conf "$TUNE_CONF"
info "TCP 基础调优参数已写入 $TUNE_CONF 并应用。"

# ---------- 3.1 设置 initcwnd / initrwnd ----------
step "3.1 设置 initcwnd=32"

if command -v ip >/dev/null 2>&1 && ip route show default >/dev/null 2>&1; then
  # || true 防止 head 提前关闭管道时 pipefail 让赋值失败
  DEFAULT_ROUTE=$(ip route show default 2>/dev/null | head -1 || true)
  if [[ -n "$DEFAULT_ROUTE" ]]; then
    read -r -a ROUTE_PARTS <<< "$DEFAULT_ROUTE"
    if ip route replace "${ROUTE_PARTS[@]}" initcwnd 32 initrwnd 32 2>/dev/null; then
      info "已为默认路由设置 initcwnd/initrwnd=32"
    elif ip route replace "${ROUTE_PARTS[@]}" initcwnd 32 2>/dev/null; then
      info "已为默认路由设置 initcwnd=32（当前 iproute2 不支持 initrwnd）"
    else
      warn "设置 initcwnd 失败（内核或 iproute2 不支持，可忽略）"
    fi
  fi
fi

# 持久化：systemd oneshot（重启后重新应用）
mkdir -p /usr/local/sbin
cat > /usr/local/sbin/set-initcwnd.sh <<'EOF'
#!/bin/bash
# 重启后恢复 initcwnd=32；不支持 initrwnd 时自动降级
sleep 2
line=$(ip route show default 2>/dev/null | head -1)
if [[ -z "$line" ]]; then exit 0; fi
read -r -a parts <<< "$line"
ip route replace "${parts[@]}" initcwnd 32 initrwnd 32 2>/dev/null || \
  ip route replace "${parts[@]}" initcwnd 32 2>/dev/null || true
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
chmod 644 /etc/systemd/system/set-initcwnd.service

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now set-initcwnd.service >/dev/null 2>&1 \
    || warn "initcwnd 服务启用失败（可忽略）"
  info "已创建 initcwnd 持久化服务（重启后生效）"
else
  warn "未检测到 systemd，跳过 initcwnd 服务持久化"
fi

# ---------- 4. 其他补充优化 ----------
step "4. 其他补充优化"

mkdir -p /etc/systemd/system.conf.d
cat > /etc/systemd/system.conf.d/limits.conf <<'EOF'
[Manager]
DefaultLimitNOFILE=1048576
DefaultLimitNPROC=1048576
EOF
chmod 644 /etc/systemd/system.conf.d/limits.conf
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
info "已提高 systemd 默认文件描述符限制。"

# ---------- 5. 调用原有 SSH 加固脚本 ----------
step "5. 执行 SSH 安全加固（调用仓库原有脚本）"

REPO='GeQian233/ssh-hardening'
BRANCH='main'
HARDEN_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/ssh-hardening.sh"
TMP_HARDEN="$(mktemp /tmp/ssh-hardening.XXXXXX.sh)"

info "正在下载原有 SSH 加固脚本..."
if command -v curl >/dev/null 2>&1; then
  curl -fLsS --retry 3 --connect-timeout 15 "$HARDEN_URL" -o "$TMP_HARDEN" \
    || { err "下载失败"; exit 1; }
elif command -v wget >/dev/null 2>&1; then
  wget -q --timeout=15 -O "$TMP_HARDEN" "$HARDEN_URL" \
    || { err "下载失败"; exit 1; }
else
  err "缺少 curl 或 wget"
  exit 1
fi

[[ -s "$TMP_HARDEN" ]] || { err "下载文件为空"; exit 1; }
head -n1 "$TMP_HARDEN" | grep -qE '^#!/usr/bin/env bash' \
  || { err "脚本格式不正确（首行不是 #!/usr/bin/env bash）"; exit 1; }
bash -n "$TMP_HARDEN" || { err "语法检查失败"; exit 1; }

info "下载及检查通过，开始执行 SSH 加固（需要交互输入端口和公钥）..."
warn "请确保云厂商安全组已放行即将使用的新 SSH 端口。"
warn "执行期间请保持当前 SSH 会话，新端口登录成功前不要关闭。"

# 使用真实终端执行，保证交互正常；不用 exec，保证 EXIT trap 清理临时文件
bash "$TMP_HARDEN" < /dev/tty
