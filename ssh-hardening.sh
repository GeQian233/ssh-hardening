#!/usr/bin/env bash
# Ubuntu 24.04+ / Debian 12+ SSH 安全加固 V5.1
# - 自动识别 Ubuntu / Debian
# - 自动识别当前 SSH 端口，允许指定新的 SSH 端口（不能与旧端口相同）
# - 安装公钥、禁用密码及键盘交互认证
# - UFW 放行新端口，确认旧端口停止监听后拒绝旧端口
# - Fail2Ban：10 分钟内失败 3 次，永久封禁
# - 兼容 ssh.socket / ssh.service，应用后执行本机验证
# - 关键步骤失败时尝试回滚 SSH / UFW / Fail2Ban 配置
#
# 使用：chmod 700 ssh-harden-debian-ubuntu-v5.1.sh
#       sudo bash ssh-harden-debian-ubuntu-v5.1.sh
#
# 注意：脚本会自动识别当前 SSH 端口；新端口需先在云厂商安全组放行。
# 保留当前 SSH 会话，新端口登录成功前不要关闭旧会话。首次启用 UFW 可能影响其他入站业务。

set -Eeuo pipefail
umask 077

DROPIN=/etc/ssh/sshd_config.d/00-ssh-hardening.conf
SOCKET_DIR=/etc/systemd/system/ssh.socket.d
SOCKET_FILE=$SOCKET_DIR/override.conf
JAIL=/etc/fail2ban/jail.d/zzzz-ssh-hardening.local
BACKUP="/root/ssh-hardening-backup-$(date +%Y%m%d-%H%M%S)"
PORT=""
OLD_PORT=""
USER_NAME="${TARGET_USER:-}"
CHANGES=0
COMMITTED=0
UFW_WAS_ACTIVE=0
UFW_ENABLED_BY_SCRIPT=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info(){ echo -e "${GREEN}[INFO]${NC} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
err(){ echo -e "${RED}[ERROR]${NC} $*" >&2; }

rollback(){
    local rc="${1:-$?}"
    trap - ERR
    if [[ $CHANGES -eq 1 && $COMMITTED -eq 0 ]]; then
        warn "执行失败，正在尝试回滚配置……"
        if [[ -d "$BACKUP/etc-ssh" ]]; then
            rm -rf /etc/ssh
            cp -a "$BACKUP/etc-ssh" /etc/ssh
        fi
        if [[ -f "$BACKUP/fail2ban.present" ]]; then
            rm -rf /etc/fail2ban
            cp -a "$BACKUP/etc-fail2ban" /etc/fail2ban
        elif [[ -d /etc/fail2ban ]]; then
            rm -f "$JAIL"
        fi
        if [[ -f "$BACKUP/ufw.present" ]]; then
            rm -rf /etc/ufw
            cp -a "$BACKUP/etc-ufw" /etc/ufw
        fi
        systemctl daemon-reload >/dev/null 2>&1 || true
        if systemctl is-active --quiet ssh.socket 2>/dev/null; then
            systemctl restart ssh.socket >/dev/null 2>&1 || true
            systemctl restart ssh.service >/dev/null 2>&1 || true
        else
            systemctl restart ssh.service >/dev/null 2>&1 ||
                systemctl restart ssh >/dev/null 2>&1 ||
                systemctl restart sshd >/dev/null 2>&1 || true
        fi
        if command -v ufw >/dev/null 2>&1; then
            if [[ $UFW_WAS_ACTIVE -eq 0 && $UFW_ENABLED_BY_SCRIPT -eq 1 ]]; then
                ufw --force disable >/dev/null 2>&1 || true
            else
                ufw reload >/dev/null 2>&1 || true
            fi
        fi
        systemctl restart fail2ban >/dev/null 2>&1 || true
        warn "已尝试回滚；请通过云厂商控制台核对。备份：$BACKUP"
    fi
    exit "$rc"
}
die(){ err "$*"; rollback 1; }
trap 'rollback $?' ERR

[[ $EUID -eq 0 ]] || die "请使用 root 运行：sudo bash $0"
[[ -r /etc/os-release ]] || die "无法识别系统。"
. /etc/os-release
case "${ID:-}" in
    ubuntu)
        OS_NAME="Ubuntu"
        dpkg --compare-versions "${VERSION_ID:-0}" ge 24.04 || die "V5.1 最低支持 Ubuntu 24.04；当前：${PRETTY_NAME:-unknown}。未修改任何配置。"
        ;;
    debian)
        OS_NAME="Debian"
        dpkg --compare-versions "${VERSION_ID:-0}" ge 12 || die "V5.1 最低支持 Debian 12；当前：${PRETTY_NAME:-unknown}。未修改任何配置。"
        ;;
    *) die "仅支持 Ubuntu 24.04+ / Debian 12+，当前系统：${PRETTY_NAME:-unknown}。未修改任何配置。";;
esac

# ---------- 自动依赖修复 + 兼容性预检 ----------
# 只通过当前发行版官方 APT 软件源安装/升级必要软件包，不添加第三方源，
# 不执行 dist-upgrade/full-upgrade。若仓库候选版本仍不达标，后续版本检查会停止。
command -v dpkg >/dev/null 2>&1 || die "缺少 dpkg，无法安全比较软件版本。"
command -v dpkg-query >/dev/null 2>&1 || die "缺少 dpkg-query。"
command -v systemctl >/dev/null 2>&1 || die "未检测到 systemd；当前脚本不支持非 systemd 系统。"
command -v apt-get >/dev/null 2>&1 || die "未检测到 apt-get。"

info "检查并自动安装/升级必要组件（仅使用系统现有 APT 软件源）……"
export DEBIAN_FRONTEND=noninteractive
APT_PACKAGES=(
    systemd
    openssh-server
    ufw
    fail2ban
    iproute2
    iptables
    nftables
    python3-systemd
)
if ! apt-get update; then
    die "APT 软件源更新失败。请检查 DNS、网络、软件源和系统时间；尚未修改 SSH/UFW/Fail2Ban 配置。"
fi
if ! apt-get install -y --no-install-recommends \
    -o Dpkg::Options::=--force-confold \
    "${APT_PACKAGES[@]}"; then
    die "必要组件自动安装/升级失败。请检查 apt 输出、磁盘空间及软件包锁；尚未开始 SSH 安全加固。"
fi

# 若 systemd 套件升级，重新执行 systemd manager 以加载当前磁盘上的版本。
systemctl daemon-reexec >/dev/null 2>&1 || warn "systemd daemon-reexec 未成功；继续进行版本检测，若服务管理异常将停止。"

command -v ss >/dev/null 2>&1 || die "安装 iproute2 后仍缺少 ss 命令。"
for cmd in sshd ssh-keygen ufw fail2ban-client iptables ip6tables; do
    command -v "$cmd" >/dev/null 2>&1 || die "自动安装后仍缺少必要命令：$cmd。停止执行。"
done

version_ge() {
    local actual="$1" minimum="$2" label="$3"
    dpkg --compare-versions "$actual" ge "$minimum" || die "$label 版本仍然过低：$actual；最低要求：$minimum。当前 APT 源可能未提供合格版本，未开始修改 SSH/UFW/Fail2Ban 配置。"
}

SYSTEMD_VERSION="$(systemctl --version | awk 'NR==1 {print $2}')"
[[ "$SYSTEMD_VERSION" =~ ^[0-9]+$ ]] || die "无法识别 systemd 版本；未修改任何配置。"
version_ge "$SYSTEMD_VERSION" 252 "systemd"

SSHD_VERSION_RAW="$(sshd -V 2>&1 || true)"
SSHD_VERSION="$(sed -nE 's/.*OpenSSH_([0-9]+\.[0-9]+(p[0-9]+)?).*/\1/p' <<< "$SSHD_VERSION_RAW" | head -n1)"
[[ -n "$SSHD_VERSION" ]] || die "无法识别 OpenSSH 版本：$SSHD_VERSION_RAW。未修改任何配置。"
version_ge "$SSHD_VERSION" 9.2p1 "OpenSSH"

UFW_VERSION_RAW="$(ufw --version 2>&1 | head -n1)"
UFW_VERSION="$(sed -nE 's/.*ufw ([0-9]+\.[0-9]+(\.[0-9]+)?).*/\1/p' <<< "$UFW_VERSION_RAW")"
[[ -n "$UFW_VERSION" ]] || die "无法识别 UFW 版本：$UFW_VERSION_RAW。未修改任何配置。"
version_ge "$UFW_VERSION" 0.36.2 "UFW"

F2B_VERSION_RAW="$(fail2ban-client --version 2>&1 | head -n1)"
F2B_VERSION="$(sed -nE 's/.*[vV]([0-9]+\.[0-9]+(\.[0-9]+)?).*/\1/p' <<< "$F2B_VERSION_RAW")"
[[ -n "$F2B_VERSION" ]] || die "无法识别 Fail2Ban 版本：$F2B_VERSION_RAW。未修改任何配置。"
version_ge "$F2B_VERSION" 1.0.2 "Fail2Ban"

# 确认 Fail2Ban 的 systemd 日志后端依赖及 UFW action 均存在。
dpkg-query -W -f='${Status}' python3-systemd 2>/dev/null | grep -q 'install ok installed' ||
    die "缺少 python3-systemd，Fail2Ban 无法可靠使用 systemd 日志后端。请先安装；本次未修改任何配置。"
[[ -f /etc/fail2ban/action.d/ufw.conf ]] || die "Fail2Ban 缺少 ufw action 文件；本次未修改任何配置。"

# 检测 systemd socket activation，不仅检查单元是否存在，也检查当前是否 active。
SSH_SOCKET_LOAD="$(systemctl show ssh.socket -p LoadState --value 2>/dev/null || echo not-found)"
SSH_SOCKET_ACTIVE=0
SSH_SOCKET_ENABLED="not-found"
if [[ "$SSH_SOCKET_LOAD" == "loaded" ]]; then
    SSH_SOCKET_ENABLED="$(systemctl is-enabled ssh.socket 2>/dev/null || true)"
    if systemctl is-active --quiet ssh.socket 2>/dev/null; then
        SSH_SOCKET_ACTIVE=1
        SSH_SOCKET_MODE="active"
    else
        SSH_SOCKET_MODE="inactive (unit loaded; service mode currently active)"
        case "$SSH_SOCKET_ENABLED" in
            enabled|enabled-runtime)
                die "ssh.socket 已启用但当前未活动，SSH 启动模式不明确。请先检查 systemctl status ssh.socket ssh.service；未修改任何配置。"
                ;;
        esac
    fi
else
    SSH_SOCKET_MODE="not installed; traditional ssh.service mode"
fi

# 检测 iptables / ip6tables 后端；两者必须一致，避免 IPv4/IPv6 规则行为不一致。
IPTABLES_VERSION_RAW="$(iptables --version 2>&1)"
IP6TABLES_VERSION_RAW="$(ip6tables --version 2>&1)"
case "$IPTABLES_VERSION_RAW" in
    *"(nf_tables)"*) FW_BACKEND="nf_tables";;
    *"(legacy)"*) FW_BACKEND="legacy";;
    *) die "无法识别 iptables 后端：$IPTABLES_VERSION_RAW。未修改任何配置。";;
esac
case "$IP6TABLES_VERSION_RAW" in
    *"(nf_tables)"*) FW6_BACKEND="nf_tables";;
    *"(legacy)"*) FW6_BACKEND="legacy";;
    *) die "无法识别 ip6tables 后端：$IP6TABLES_VERSION_RAW。未修改任何配置。";;
esac
[[ "$FW_BACKEND" == "$FW6_BACKEND" ]] || die "IPv4/IPv6 防火墙后端不一致（$FW_BACKEND / $FW6_BACKEND），为避免规则遗漏已停止；未修改任何配置。"
if [[ "$FW_BACKEND" == "nf_tables" ]]; then
    command -v nft >/dev/null 2>&1 || die "iptables 使用 nf_tables 后端，但缺少 nft 命令；未修改任何配置。"
    NFT_VERSION="$(nft --version 2>&1 | head -n1)"
else
    NFT_VERSION="未使用（iptables legacy 后端）"
fi

# 检查当前 sshd 配置语法与服务状态，确保不是在不完整环境中开始修改。
sshd -t || die "当前 OpenSSH 配置本身检查失败；请先修复现有配置。未修改任何配置。"
fail2ban-client -t >/dev/null 2>&1 || die "当前 Fail2Ban 配置检查失败；请先修复现有配置。未修改任何配置。"
ufw status >/dev/null 2>&1 || die "UFW 当前无法正常读取状态；请先修复 UFW。未修改任何配置。"
if ! systemctl is-active --quiet ssh.service 2>/dev/null &&
   ! systemctl is-active --quiet ssh 2>/dev/null &&
   ! systemctl is-active --quiet sshd 2>/dev/null &&
   [[ "$SSH_SOCKET_ACTIVE" -ne 1 ]]; then
    die "未检测到运行中的 ssh.service 或 ssh.socket；请先确认 SSH 服务状态。未修改任何配置。"
fi

info "自动依赖安装/升级及兼容性预检全部通过：${PRETTY_NAME:-$OS_NAME}"
echo "  systemd：$SYSTEMD_VERSION"
echo "  OpenSSH：$SSHD_VERSION"
echo "  UFW：$UFW_VERSION"
echo "  Fail2Ban：$F2B_VERSION"
echo "  SSH socket activation：$SSH_SOCKET_MODE（enabled=$SSH_SOCKET_ENABLED）"
echo "  防火墙后端：IPv4=$FW_BACKEND；IPv6=$FW6_BACKEND"
echo "  nftables：$NFT_VERSION"
echo "  Fail2Ban systemd backend：python3-systemd 已安装"
info "预检阶段未修改任何 SSH / UFW / Fail2Ban 配置。"

# 自动识别当前 SSH 端口。优先使用当前 SSH 会话环境变量，
# 其次读取 ssh.socket / 已建立 SSH 连接 / sshd 监听端口。
declare -A SSH_PORT_CANDIDATES=()
add_ssh_port_candidate() {
    local candidate="${1:-}"
    if [[ "$candidate" =~ ^[0-9]{1,5}$ ]] && (( candidate >= 1 && candidate <= 65535 )); then
        SSH_PORT_CANDIDATES["$candidate"]=1
    fi
}

if [[ -n "${SSH_CONNECTION:-}" ]]; then
    add_ssh_port_candidate "$(awk '{print $4}' <<< "$SSH_CONNECTION")"
fi

if systemctl is-active --quiet ssh.socket 2>/dev/null; then
    while read -r candidate; do add_ssh_port_candidate "$candidate"; done < <(
        systemctl show ssh.socket -p Listen --value 2>/dev/null |
        grep -oE ':[0-9]{1,5}([[:space:]]|$)' | grep -oE '[0-9]+' || true
    )
fi

# 已建立的 SSH 连接能反映当前实际使用的服务端端口。
while read -r candidate; do add_ssh_port_candidate "$candidate"; done < <(
    ss -H -tnp state established 2>/dev/null |
    awk '/sshd/ {print $3}' |
    sed -nE 's/.*:([0-9]+)$/\1/p' || true
)

# 若以上没有识别到，再从 sshd 监听套接字和 sshd 有效配置兜底。
if (( ${#SSH_PORT_CANDIDATES[@]} == 0 )); then
    while read -r candidate; do add_ssh_port_candidate "$candidate"; done < <(
        ss -H -ltnp 2>/dev/null |
        awk '/sshd/ {print $4}' |
        sed -nE 's/.*:([0-9]+)$/\1/p' || true
    )
fi
if (( ${#SSH_PORT_CANDIDATES[@]} == 0 )) && command -v sshd >/dev/null 2>&1; then
    while read -r candidate; do add_ssh_port_candidate "$candidate"; done < <(
        sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' || true
    )
fi

# 当前会话信息优先级最高；即使服务器还监听其他 SSH 端口，也以本会话服务端端口为准。
if [[ -n "${SSH_CONNECTION:-}" ]]; then
    SESSION_PORT="$(awk '{print $4}' <<< "$SSH_CONNECTION")"
    if [[ "$SESSION_PORT" =~ ^[0-9]{1,5}$ ]] && (( SESSION_PORT >= 1 && SESSION_PORT <= 65535 )); then
        OLD_PORT="$SESSION_PORT"
    fi
fi

if [[ -z "$OLD_PORT" ]]; then
    if (( ${#SSH_PORT_CANDIDATES[@]} == 1 )); then
        OLD_PORT="${!SSH_PORT_CANDIDATES[@]}"
    elif (( ${#SSH_PORT_CANDIDATES[@]} > 1 )); then
        echo "检测到多个本机 SSH 服务端口：${!SSH_PORT_CANDIDATES[*]}"
        read -rp "请输入当前 SSH 登录使用的服务端端口: " OLD_PORT
        [[ "$OLD_PORT" =~ ^[0-9]{1,5}$ ]] &&
        (( OLD_PORT >= 1 && OLD_PORT <= 65535 )) &&
        [[ -n "${SSH_PORT_CANDIDATES[$OLD_PORT]+x}" ]] ||
            die "输入的端口不在检测到的本机 SSH 服务端口列表中。"
    else
        die "无法自动识别当前 SSH 端口。请确认 sshd/ssh.socket 正在运行，并从 SSH 远程会话执行脚本。"
    fi
fi

info "自动识别到当前 SSH 端口：$OLD_PORT/tcp"

echo "=================================================="
echo " Ubuntu 24.04+ / Debian 12+ SSH 安全加固脚本 V5.1"
echo "=================================================="
warn "执行前请确认可以修改云厂商安全组；执行期间保持当前 SSH 会话。"
echo

# 只接受当前没有任何 TCP 监听进程占用的新端口。
# 不论占用者是 sshd、Web 服务、Docker 代理还是其他程序，都不能直接复用。
port_is_free() {
    local port="$1"
    ! ss -H -ltn "sport = :$port" 2>/dev/null | grep -q .
}

while true; do
    read -rp "请输入新的 SSH TCP 端口（1-65535，不能为 22，也不能与当前端口 $OLD_PORT 相同）: " PORT
    if ! [[ "$PORT" =~ ^[0-9]{1,5}$ ]] || (( PORT < 1 || PORT > 65535 || PORT == 22 || PORT == OLD_PORT )); then
        warn "端口无效、不能使用 22，或与当前 SSH 端口相同，请重新输入。"
        continue
    fi

    if ! port_is_free "$PORT"; then
        warn "TCP 端口 $PORT 当前已被占用，以下为占用信息："
        ss -H -ltnp "sport = :$PORT" 2>/dev/null || true
        warn "请重新输入一个当前未被占用的端口。"
        continue
    fi
    break
done

info "新 SSH 端口设置为：$PORT/tcp（检查时未发现 TCP 监听占用）"
warn "请确保云厂商安全组/外部防火墙已放行 $PORT/tcp；脚本无法替你修改厂商安全组。"

if [[ -z "$USER_NAME" ]]; then
    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]]; then
        USER_NAME=$SUDO_USER
    else
        read -rp "安装公钥的 Linux 用户 [root]: " USER_NAME
        USER_NAME="${USER_NAME:-root}"
    fi
fi
getent passwd "$USER_NAME" >/dev/null || die "用户不存在：$USER_NAME"
HOME_DIR="$(getent passwd "$USER_NAME" | awk -F: '{print $6}')"
GROUP_NAME="$(id -gn "$USER_NAME")"
[[ -n "$HOME_DIR" && -d "$HOME_DIR" ]] || die "无法获取用户家目录。"

# 循环读取并校验公钥；格式错误时不退出，允许用户重新粘贴。
while true; do
    echo "请粘贴一整行 SSH 公钥（推荐 ssh-ed25519）："
    if ! IFS= read -r PUBKEY; then
        die "未能读取 SSH 公钥输入。"
    fi

    if [[ -z "${PUBKEY//[[:space:]]/}" ]]; then
        warn "公钥不能为空，请重新输入。"
        continue
    fi

    case "$PUBKEY" in
        ssh-ed25519\ *|ecdsa-sha2-nistp256\ *|ecdsa-sha2-nistp384\ *|ecdsa-sha2-nistp521\ *|ssh-rsa\ *)
            ;;
        *)
            warn "公钥类型不支持或格式不正确。仅支持 Ed25519、ECDSA、RSA，请重新输入。"
            continue
            ;;
    esac

    TMP_KEY="$(mktemp)"
    printf '%s\n' "$PUBKEY" > "$TMP_KEY"
    if ssh-keygen -lf "$TMP_KEY" >/dev/null 2>&1; then
        KEY_FINGERPRINT="$(ssh-keygen -lf "$TMP_KEY" 2>/dev/null | awk '{print $2}')"
        rm -f "$TMP_KEY"
        info "公钥格式校验通过：$KEY_FINGERPRINT"
        break
    else
        rm -f "$TMP_KEY"
        warn "公钥内容校验失败，请粘贴 .pub 文件中的完整一行后重试。"
    fi
done

if ufw status 2>/dev/null | grep -q '^Status: active'; then
    UFW_WAS_ACTIVE=1
else
    warn "UFW 当前未启用。启用后，未放行的 Web、面板等入站业务可能被阻断。"
    read -rp "确认启用 UFW？请确保其他业务端口已有放行规则。(y/N): " ans
    [[ "$ans" =~ ^[Yy]$ ]] || die "你选择不启用 UFW，脚本退出。"
fi

# 备份整个配置目录，失败时恢复。
port_is_free "$PORT" || die "端口 $PORT 在准备修改 SSH 配置前已被占用，请重新运行脚本并选择其他端口。"

mkdir -p "$BACKUP"
cp -a /etc/ssh "$BACKUP/etc-ssh"
if [[ -d /etc/fail2ban ]]; then
    cp -a /etc/fail2ban "$BACKUP/etc-fail2ban"
    touch "$BACKUP/fail2ban.present"
fi
if [[ -d /etc/ufw ]]; then
    cp -a /etc/ufw "$BACKUP/etc-ufw"
    touch "$BACKUP/ufw.present"
fi
CHANGES=1
info "备份完成：$BACKUP"

# 安装公钥并设置安全权限。
SSH_DIR="$HOME_DIR/.ssh"
AUTH="$SSH_DIR/authorized_keys"
install -d -m 700 -o "$USER_NAME" -g "$GROUP_NAME" "$SSH_DIR"
touch "$AUTH"
chown "$USER_NAME:$GROUP_NAME" "$AUTH"
chmod 600 "$AUTH"
grep -Fqx -- "$PUBKEY" "$AUTH" || printf '%s\n' "$PUBKEY" >> "$AUTH"
chown "$USER_NAME:$GROUP_NAME" "$AUTH"
chmod 600 "$AUTH"

# 把 Include 放在主配置最前面，确保 00 drop-in 优先。
mkdir -p /etc/ssh/sshd_config.d
if ! head -n 1 /etc/ssh/sshd_config | grep -Fq 'Include /etc/ssh/sshd_config.d/*.conf'; then
    tmp="$(mktemp)"
    { echo 'Include /etc/ssh/sshd_config.d/*.conf'; cat /etc/ssh/sshd_config; } > "$tmp"
    cat "$tmp" > /etc/ssh/sshd_config
    rm -f "$tmp"
fi

# Port 指令会累加；注释 sshd 主配置及顶层 drop-in 的旧 Port。
while IFS= read -r -d '' f; do
    [[ "$f" == "$DROPIN" ]] && continue
    sed -i -E '/^[[:space:]]*[Pp][Oo][Rr][Tt][[:space:]]+/s/^/# disabled by ssh-hardening-v5.1: /' "$f"
done < <(
    {
        printf '%s\0' /etc/ssh/sshd_config
        find /etc/ssh/sshd_config.d -maxdepth 1 -type f -name '*.conf' -print0 2>/dev/null || true
    }
)

cat > "$DROPIN" <<EOF
# Managed by ssh-harden-debian-ubuntu-v5.1.sh
Port $PORT
AddressFamily any
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitEmptyPasswords no
PermitRootLogin prohibit-password
UsePAM yes
MaxAuthTries 3
EOF
chmod 644 "$DROPIN"

sshd -t
EFFECTIVE="$(sshd -T -C "user=$USER_NAME,host=localhost,addr=127.0.0.1")"
check_value(){
    local key="$1" want="$2" got
    got="$(awk -v k="$key" '$1==k {$1=""; sub(/^ /,""); print; exit}' <<< "$EFFECTIVE")"
    [[ "$got" == "$want" ]] || die "SSH 有效配置错误：$key=$got，预期 $want。"
}
check_value port "$PORT"
check_value pubkeyauthentication yes
check_value authenticationmethods publickey
check_value passwordauthentication no
check_value kbdinteractiveauthentication no
check_value permitemptypasswords no
info "SSH 语法和认证配置检查通过。"

# 先放行新端口，暂时保留旧端口作为回退通道。
ufw allow "$PORT/tcp" comment "SSH custom port $PORT" >/dev/null
ufw allow "$OLD_PORT/tcp" comment "Temporary SSH rollback access" >/dev/null
if [[ $UFW_WAS_ACTIVE -eq 0 ]]; then
    ufw --force enable
    UFW_ENABLED_BY_SCRIPT=1
fi
ufw reload >/dev/null

# 安装并配置 Fail2Ban。

mkdir -p /etc/fail2ban/jail.d
cat > "$JAIL" <<EOF
# Managed by ssh-harden-debian-ubuntu-v5.1.sh
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime = -1
findtime = 10m
maxretry = 3
backend = systemd
banaction = ufw

[sshd]
enabled = true
port = $PORT
filter = sshd
backend = systemd
maxretry = 3
findtime = 10m
bantime = -1
EOF
# 先验证配置语法，再启动服务；systemctl 返回不代表 Fail2Ban socket 已可用。
fail2ban-client -t
systemctl enable fail2ban >/dev/null
systemctl restart fail2ban

F2B_READY=0
for _ in $(seq 1 30); do
    if systemctl is-active --quiet fail2ban &&
       [[ -S /run/fail2ban/fail2ban.sock || -S /var/run/fail2ban/fail2ban.sock ]] &&
       fail2ban-client ping 2>/dev/null | grep -q 'Server replied: pong'; then
        F2B_READY=1
        break
    fi
    sleep 1
done
[[ $F2B_READY -eq 1 ]] || {
    journalctl -u fail2ban -n 40 --no-pager >&2 || true
    die "Fail2Ban 在 30 秒内未能就绪（服务/socket/ping 检查失败）。"
}

# 校验运行中的 jail 参数，而不是只检查配置文件文本。
fail2ban-client status sshd >/dev/null ||
    die "Fail2Ban sshd jail 未启动。"

ACTUAL_MAXRETRY="$(fail2ban-client get sshd maxretry 2>/dev/null | tail -n 1 | tr -d '[:space:]')"
ACTUAL_BANTIME="$(fail2ban-client get sshd bantime 2>/dev/null | tail -n 1 | tr -d '[:space:]')"
ACTUAL_FINDTIME="$(fail2ban-client get sshd findtime 2>/dev/null | tail -n 1 | tr -d '[:space:]')"
[[ "$ACTUAL_MAXRETRY" == "3" ]] ||
    die "Fail2Ban 实际 maxretry=$ACTUAL_MAXRETRY，不是 3。"
[[ "$ACTUAL_BANTIME" == "-1" ]] ||
    die "Fail2Ban 实际 bantime=$ACTUAL_BANTIME，不是永久封禁 -1。"
[[ "$ACTUAL_FINDTIME" == "600" || "$ACTUAL_FINDTIME" == "10m" ]] ||
    die "Fail2Ban 实际 findtime=$ACTUAL_FINDTIME，不是 10 分钟。"

# 从 Fail2Ban 解析后的配置中确认 jail action 使用新端口。
F2B_DUMP="$(fail2ban-client -d 2>&1)"
grep -Fq "['port', '$PORT']" <<< "$F2B_DUMP" ||
    die "Fail2Ban 解析后的 sshd action 端口不是 $PORT。"
grep -Fq "['set', 'sshd', 'addaction', 'ufw']" <<< "$F2B_DUMP" ||
    die "Fail2Ban 实际封禁动作不是 UFW。"

# 应用 SSH 配置：socket activation 和传统服务分别处理。
if [[ "$SSH_SOCKET_ACTIVE" -eq 1 ]]; then
    info "检测到活动的 ssh.socket，更新 Socket 和 SSH 服务。"
    mkdir -p "$SOCKET_DIR"
    cat > "$SOCKET_FILE" <<EOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:$PORT
ListenStream=[::]:$PORT
EOF
    systemctl daemon-reload
    systemctl restart ssh.socket
    systemctl restart ssh.service
else
    info "使用传统 ssh.service。"
    systemctl restart ssh.service 2>/dev/null ||
        systemctl restart ssh 2>/dev/null ||
        systemctl restart sshd
fi

# 检查新端口监听。
LISTEN_OK=0
for _ in $(seq 1 20); do
    if ss -H -ltn "sport = :$PORT" 2>/dev/null | grep -q .; then
        LISTEN_OK=1
        break
    fi
    sleep 1
done
[[ $LISTEN_OK -eq 1 ]] || die "新 SSH 端口 $PORT 没有开始监听。"

# 确认旧 SSH 端口已不再监听，然后移除临时 ALLOW，再添加最终 DENY。
if ss -H -ltn "sport = :$OLD_PORT" 2>/dev/null | grep -q .; then
    ss -lntp | grep -E "(:$OLD_PORT[[:space:]]|:$OLD_PORT$)" || true
    die "原 SSH 端口 $OLD_PORT 仍有进程监听，停止并回滚。"
fi

# 删除前面为回退临时添加的旧端口 ALLOW 规则。
# UFW 会同步管理 IPv4/IPv6 规则；规则不存在时忽略删除错误。
ufw --force delete allow "$OLD_PORT/tcp" >/dev/null 2>&1 || true

# 添加旧端口 DENY 规则，并重新加载防火墙。
ufw insert 1 deny "$OLD_PORT/tcp"
ufw reload >/dev/null
ufw status numbered

# 最终重新读取并验证 SSH 的有效配置。
sshd -t
FINAL="$(sshd -T -C "user=$USER_NAME,host=localhost,addr=127.0.0.1")"
for item in \
    "port $PORT" \
    "pubkeyauthentication yes" \
    "authenticationmethods publickey" \
    "passwordauthentication no" \
    "kbdinteractiveauthentication no" \
    "permitemptypasswords no"; do
    grep -Fxq "$item" <<< "$FINAL" || die "最终 SSH 配置验证失败：$item"
done
ss -H -ltn "sport = :$PORT" | grep -q . || die "最终检查：新端口未监听。"
! ss -H -ltn "sport = :$OLD_PORT" | grep -q . || die "最终检查：旧 SSH 端口仍在监听。"

# 最终检查 UFW 和 Fail2Ban。
UFW_STATUS="$(ufw status)"
grep -q '^Status: active' <<< "$UFW_STATUS" || die "UFW 未启用。当前状态：$(head -n 1 <<< "$UFW_STATUS")"

# 解析 ufw status 规则表，兼容 IPv4 与带 (v6) 标记的 IPv6 行。
# 例如：22/tcp DENY IN Anywhere；22/tcp (v6) DENY IN Anywhere (v6)
ufw_rule_exists() {
    local wanted_port="$1" wanted_action="$2" status
    status="$(ufw status 2>/dev/null)" || return 2
    awk -v p="$wanted_port" -v a="$wanted_action" '
        $1 == p && $2 == a { found=1 }
        $1 == p && $2 == "(v6)" && $3 == a { found=1 }
        END { exit !found }
    ' <<< "$status"
}

ufw_rule_exists "$PORT/tcp" ALLOW || {
    ufw status numbered >&2 || true
    die "UFW 未检测到新 SSH 端口 $PORT/tcp 的 ALLOW 规则。"
}
ufw_rule_exists "$OLD_PORT/tcp" DENY || {
    ufw status >&2 || true
    ufw status numbered >&2 || true
    die "UFW 未检测到旧 SSH 端口 $OLD_PORT/tcp 的 DENY 规则。"
}

fail2ban-client -t >/dev/null || die "Fail2Ban 配置检查失败。"
systemctl is-active --quiet fail2ban || die "Fail2Ban 服务未运行。"
fail2ban-client ping 2>/dev/null | grep -q 'Server replied: pong' || die "Fail2Ban socket 无法通信。"
fail2ban-client status sshd >/dev/null || die "Fail2Ban sshd jail 不可用。"
[[ "$(fail2ban-client get sshd maxretry 2>/dev/null | tail -n 1 | tr -d '[:space:]')" == "3" ]] || die "Fail2Ban 实际失败次数不是 3。"
[[ "$(fail2ban-client get sshd bantime 2>/dev/null | tail -n 1 | tr -d '[:space:]')" == "-1" ]] || die "Fail2Ban 实际封禁时间不是永久。"
F2B_FINAL_DUMP="$(fail2ban-client -d 2>&1)"
grep -Fq "['port', '$PORT']" <<< "$F2B_FINAL_DUMP" || die "Fail2Ban 实际监听端口与 SSH 端口不一致。"
grep -Fq "['set', 'sshd', 'addaction', 'ufw']" <<< "$F2B_FINAL_DUMP" || die "Fail2Ban 实际封禁动作不是 UFW。"

# 所有本机检查通过后才报告成功。
COMMITTED=1
trap - ERR
echo
echo "=================================================="
echo -e "${GREEN}已成功修改${NC}"
echo "=================================================="
echo "系统：${PRETTY_NAME:-$OS_NAME}"
echo "SSH 用户：$USER_NAME"
echo "SSH 端口：$PORT/tcp"
echo "密码登录：已禁用"
echo "键盘交互认证：已禁用"
echo "公钥认证：已启用并强制使用"
echo "原 SSH 端口：$OLD_PORT/tcp（已确认无监听，UFW 已拒绝）"
echo "新 SSH 端口：$PORT/tcp（UFW 已放行）"
echo "Fail2Ban：监听 SSH $PORT，实际参数已核验"
echo "封禁策略：10 分钟内失败 3 次，永久封禁"
echo "备份目录：$BACKUP"
echo
echo "当前监听："
ss -lntp | grep -E ":($PORT|$OLD_PORT)([[:space:]]|$)" || true
echo
fail2ban-client status sshd
echo
echo "请在新终端测试："
echo "ssh -p $PORT $USER_NAME@服务器公网IP"
echo "请在云厂商安全组/防火墙中放行新端口 $PORT/tcp。"
echo "原 SSH 端口 $OLD_PORT/tcp 已在服务器本机 UFW 中封禁。"
echo "新端口登录成功后，再关闭当前旧 SSH 会话。"
echo
echo "解封 IP：fail2ban-client set sshd unbanip <IP地址>"
echo "查看封禁：fail2ban-client get sshd banip"
echo "查看防火墙：ufw status numbered"
warn "以上为服务器本机验证；云安全组、上游防火墙及客户端私钥仍需通过实际登录确认。"
echo "=================================================="
exit 0
