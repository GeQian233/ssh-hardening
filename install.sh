#!/usr/bin/env bash
# One-line installer for GeQian233/ssh-hardening
# 支持 curl | sudo bash 以及先下载再执行两种方式
set -Eeuo pipefail

REPO='GeQian233/ssh-hardening'
BRANCH='main'
SCRIPT='ssh-hardening.sh'
URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/${SCRIPT}"

# 颜色（可选，终端不支持时自动降级）
if [[ -t 1 ]]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  NC='\033[0m'
else
  RED='' GREEN='' YELLOW='' NC=''
fi

info()  { printf "${GREEN}[INFO]${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${NC} %s\n" "$*" >&2; }
error() { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; exit 1; }

# 必须 root
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  error '请使用 root 运行：curl ... | sudo bash  或  sudo bash install.sh'
fi

# 检查是否存在可用的交互式终端
has_tty=false
if [[ -r /dev/tty && -w /dev/tty ]]; then
  has_tty=true
fi

# 如果当前 stdin 不是终端，且没有 /dev/tty，则无法交互
if [[ ! -t 0 ]] && [[ "$has_tty" != true ]]; then
  error '未检测到可用的交互式终端。
本脚本需要输入 SSH 端口和公钥，请在分配了 PTY 的 SSH 会话中运行。
不要使用 ssh -T 或「远程执行命令」方式。
推荐做法：
  curl -fsSL '"$URL"' -o /tmp/ssh-hardening.sh && sudo bash /tmp/ssh-hardening.sh'
fi

# 选择下载工具
if command -v curl >/dev/null 2>&1; then
  DOWNLOADER='curl'
elif command -v wget >/dev/null 2>&1; then
  DOWNLOADER='wget'
else
  error '缺少 curl 或 wget。请先安装其中一个，再重新运行。'
fi

TMP_SCRIPT="$(mktemp /tmp/ssh-hardening.XXXXXX.sh)"
cleanup() { rm -f "$TMP_SCRIPT"; }
trap cleanup EXIT

info "正在从 GitHub 下载 SSH 加固脚本……"

if [[ "$DOWNLOADER" == 'curl' ]]; then
  if ! curl -fLsS --retry 3 --connect-timeout 15 "$URL" -o "$TMP_SCRIPT"; then
    error "下载失败：$URL"
  fi
else
  if ! wget -q --timeout=15 -O "$TMP_SCRIPT" "$URL"; then
    error "下载失败：$URL"
  fi
fi

# 基本完整性检查
if [[ ! -s "$TMP_SCRIPT" ]]; then
  error '下载文件为空，拒绝执行。'
fi

if ! head -n 1 "$TMP_SCRIPT" | grep -qE '^#!/usr/bin/env bash'; then
  error '下载文件格式不正确（缺少 shebang），拒绝执行。'
fi

# 语法检查
if ! bash -n "$TMP_SCRIPT"; then
  error '核心脚本 Bash 语法检查失败，拒绝执行。'
fi

info "下载及语法检查通过，启动 SSH 安全加固……"

# 执行核心脚本
# 如果当前 stdin 不是终端，则强制从 /dev/tty 读取
if [[ ! -t 0 ]] && [[ "$has_tty" == true ]]; then
  # 管道方式运行时，从真实终端读取输入
  exec bash "$TMP_SCRIPT" < /dev/tty
else
  # 直接执行方式，stdin 本身就是终端
  exec bash "$TMP_SCRIPT"
fi
