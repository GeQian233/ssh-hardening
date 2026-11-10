#!/usr/bin/env bash
# One-line installer for GeQian233/ssh-hardening
set -Eeuo pipefail

REPO='GeQian233/ssh-hardening'
BRANCH='main'
SCRIPT='ssh-hardening.sh'
URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/${SCRIPT}"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo '[ERROR] 请使用 root 运行：curl ... | sudo bash' >&2
  exit 1
fi

# curl | sudo bash 会占用标准输入；核心脚本需要交互输入端口和公钥，
# 因此必须从真实终端读取输入。
if [[ ! -r /dev/tty ]]; then
  echo '[ERROR] 未检测到交互式终端。本脚本需要输入 SSH 端口和公钥，请在 SSH/终端会话中运行。' >&2
  exit 1
fi

if command -v curl >/dev/null 2>&1; then
  DOWNLOADER='curl'
elif command -v wget >/dev/null 2>&1; then
  DOWNLOADER='wget'
else
  echo '[ERROR] 缺少 curl 或 wget。请先安装其中一个，再重新运行。' >&2
  exit 1
fi

TMP_SCRIPT="$(mktemp /tmp/ssh-hardening.XXXXXX.sh)"
cleanup() { rm -f "$TMP_SCRIPT"; }
trap cleanup EXIT

printf '[INFO] 正在从 GitHub 下载 SSH 加固脚本……\n'
if [[ "$DOWNLOADER" == 'curl' ]]; then
  if ! curl -fLsS --retry 3 --connect-timeout 15 "$URL" -o "$TMP_SCRIPT"; then
    echo "[ERROR] 下载失败：$URL" >&2
    exit 1
  fi
else
  if ! wget -q --timeout=15 -O "$TMP_SCRIPT" "$URL"; then
    echo "[ERROR] 下载失败：$URL" >&2
    exit 1
  fi
fi

if [[ ! -s "$TMP_SCRIPT" ]] || ! head -n 1 "$TMP_SCRIPT" | grep -qE '^#!/usr/bin/env bash'; then
  echo '[ERROR] 下载文件为空或格式不正确，拒绝执行。' >&2
  exit 1
fi

if ! bash -n "$TMP_SCRIPT"; then
  echo '[ERROR] 核心脚本 Bash 语法检查失败，拒绝执行。' >&2
  exit 1
fi

printf '[INFO] 下载及语法检查通过，启动 SSH 安全加固……\n'
bash "$TMP_SCRIPT" < /dev/tty
