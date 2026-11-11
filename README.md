# SSH Hardening for Ubuntu & Debian

Ubuntu 24.04+ / Debian 12+ SSH 一键安全加固脚本。项目通过 `install.sh` 下载并启动核心脚本。

> **重要：** 脚本会修改 SSH、UFW 和 Fail2Ban 配置，并可能启用 UFW。请先确认云厂商安全组已允许新 SSH 端口；执行期间保持当前 SSH 会话，新端口通过外部登录验证前不要关闭旧会话。
>
> 本项目当前核心脚本为 V5.1。已在维护者的 Ubuntu 26.04.1/Ubuntu 24.04 环境完成一次实际配置及新端口登录验证；Debian 12/13 的独立实机兼容性测试未知。请勿将目标兼容范围理解为所有发行版均已实测。

## 一键运行

**推荐方式（更稳定，避免部分环境下 apt 被挂起）：**

```bash
curl -fsSL https://raw.githubusercontent.com/GeQian233/ssh-hardening/main/install.sh -o /tmp/install.sh
sudo bash /tmp/install.sh
```

或者直接运行核心脚本：

```bash
curl -fsSL https://raw.githubusercontent.com/GeQian233/ssh-hardening/main/ssh-hardening.sh -o /tmp/ssh-hardening.sh
sudo bash /tmp/ssh-hardening.sh
```

---

**管道方式（部分新版 Ubuntu + sudo-rs 环境下可能卡住）：**

```bash
curl -fsSL https://raw.githubusercontent.com/GeQian233/ssh-hardening/main/install.sh | sudo bash
```

> 必须使用 Bash，不要把命令中的 `bash` 改成 `sh`。脚本需要交互式终端来输入新 SSH 端口和 SSH 公钥，因此请在正常 SSH 终端中运行，不适用于无 TTY 的自动化任务。
>
> 如果在 `Processing triggers for libc-bin` 处长时间无响应，且 `ps` 显示进程状态为 `T+`，可在原窗口执行 `fg`，或另开窗口执行 `kill -CONT <PID>` 恢复。

如果当前已经是 root：

```bash
curl -fsSL https://raw.githubusercontent.com/GeQian233/ssh-hardening/main/install.sh -o /tmp/install.sh
bash /tmp/install.sh
```

## 支持范围与依赖

目标系统：

- Ubuntu 24.04 LTS 及以上
- Debian 12 及以上

脚本会使用系统现有 APT 软件源安装或升级所需组件，不添加第三方软件源，也不执行 `dist-upgrade` / `full-upgrade`。如果软件源提供的版本仍不满足脚本最低要求，脚本会停止。

主要组件：systemd、OpenSSH Server、UFW、Fail2Ban、iproute2、iptables、nftables、python3-systemd。

## 功能

- 自动识别 Ubuntu / Debian 发行版和版本。
- 自动安装/升级所需组件并进行版本预检。
- 检查 systemd、OpenSSH、UFW、Fail2Ban 版本。
- 检测 `ssh.socket` / `ssh.service` 模式及 iptables / nftables 后端。
- 自动识别当前 SSH 端口，要求新端口未被 TCP LISTEN 占用。
- 校验 SSH 公钥格式；禁用密码和键盘交互认证。
- 配置 UFW 放行新端口，并在确认 SSH 不再监听旧端口后拒绝旧端口。
- 配置 Fail2Ban：10 分钟内失败 3 次，永久封禁。
- 关键步骤失败时尝试回滚 SSH、UFW、Fail2Ban 配置。

## 安全提示

1. 运行前先在云厂商安全组/云防火墙放行准备使用的新 TCP 端口。
2. 确保有 VPS 控制台或救援模式作为备用管理入口。
3. 保留当前 SSH 连接；新端口登录成功前不要退出。
4. UFW 启用后，未明确放行的其他入站服务可能无法访问。请提前确认 Web 面板、网站、数据库、VPN 等业务端口。
5. 脚本的配置回滚不等于系统快照；APT 已安装/升级的软件包不会自动降级或卸载。
6. Fail2Ban 永久封禁可能误封管理员 IP。确认客户端出口 IP 稳定，并掌握控制台解封方法。
7. 公钥私钥应妥善保管；不要把私钥上传到服务器或 GitHub。
8. 通过 GitHub `main` 分支运行意味着执行仓库当前版本。生产环境建议使用固定版本标签或审阅过的提交。

## 手动运行核心脚本

```bash
sudo bash ssh-hardening.sh
```

## 故障排查

- 查看 SSH：`ss -lntp`、`sshd -t`、`systemctl status ssh.service ssh.socket --no-pager`
- 查看 UFW：`ufw status numbered`
- 查看 Fail2Ban：`fail2ban-client status`、`fail2ban-client status sshd`
- 如果无法连接，优先使用云厂商 VNC/串口/救援控制台恢复，不要反复运行脚本。
- 若安装依赖时卡在 `Processing triggers for libc-bin` 且进程状态为 `T+`，在原终端执行 `fg`，或另开终端执行 `kill -CONT <PID>`。

## License

MIT License，详见仓库中的 `LICENSE` 文件。


