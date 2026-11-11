# SSH Hardening for Ubuntu & Debian

Ubuntu 24.04+ / Debian 12+ 一键系统优化 + SSH 安全加固脚本。AI搓的-不保证兼容性-自用为主

包含：系统软件包升级、启用 BBR、TCP 窗口调优，然后自动执行原有的 SSH 加固流程。

> **重要：**  
> - 脚本会升级系统软件包、修改内核网络参数、修改 SSH / UFW / Fail2Ban 配置，并可能启用 UFW。  
> - 请先确认云厂商安全组已允许新 SSH 端口。  
> - 执行期间保持当前 SSH 会话，新端口通过外部登录验证前不要关闭旧会话。  
> - 系统升级后可能需要重启才能完全生效（尤其是内核更新）。  
> - 本项目核心 SSH 加固脚本为 V5.1。已在维护者的 Ubuntu 26.04.1 / 24.04 环境验证；Debian 兼容性请自行测试。

## 一键运行（推荐）

**推荐方式（更稳定）：**

```bash
curl -fsSL https://raw.githubusercontent.com/GeQian233/ssh-hardening/main/optimize-and-harden.sh -o /tmp/optimize-and-harden.sh
sudo bash /tmp/optimize-and-harden.sh
```

或者（如果已是 root）：

```bash
curl -fsSL https://raw.githubusercontent.com/GeQian233/ssh-hardening/main/optimize-and-harden.sh -o /tmp/optimize-and-harden.sh
bash /tmp/optimize-and-harden.sh
```

> 必须使用 Bash。脚本需要交互式终端输入新 SSH 端口和公钥，请在正常 SSH 会话中运行。

### 管道方式（部分环境下可能卡住，不推荐优先使用）

```bash
curl -fsSL https://raw.githubusercontent.com/GeQian233/ssh-hardening/main/optimize-and-harden.sh | sudo bash
```

如果卡在 apt 相关步骤且进程状态为 `T+`，可在原窗口执行 `fg`，或另开窗口 `kill -CONT <PID>`。

## 脚本做了什么

1. **系统识别与升级**  
   自动识别 Ubuntu / Debian 版本，执行 `apt update` + `apt upgrade`（非交互、保留现有配置文件）。

2. **启用 BBR**  
   - 加载 `tcp_bbr` 模块并持久化  
   - 写入 `/etc/sysctl.d/99-bbr.conf`（`fq` + `bbr`）  
   - 验证当前拥塞控制算法

3. **TCP 窗口调优**  
   写入 `/etc/sysctl.d/99-tcp-tune.conf`，包含常用高性能参数（缓冲区 32MB、SACK、窗口缩放、`tcp_slow_start_after_idle=0` 等），等效于常见 tools.sh 的核心调优，但使用独立 drop-in 文件，更干净、可维护。

4. **其他补充**  
   提高 systemd 默认文件描述符限制。

5. **执行原有 SSH 加固**  
   自动下载并运行仓库中的 `ssh-hardening.sh`（公钥认证、改端口、UFW、Fail2Ban、回滚机制等全部保留）。

## 仅运行原有 SSH 加固

如果你只想做 SSH 加固，不需要系统升级和网络调优，仍可使用：

```bash
curl -fsSL https://raw.githubusercontent.com/GeQian233/ssh-hardening/main/install.sh -o /tmp/install.sh
sudo bash /tmp/install.sh
```

或直接：

```bash
curl -fsSL https://raw.githubusercontent.com/GeQian233/ssh-hardening/main/ssh-hardening.sh -o /tmp/ssh-hardening.sh
sudo bash /tmp/ssh-hardening.sh
```

## 支持范围

- Ubuntu 24.04 LTS 及以上
- Debian 12 及以上

## 安全提示

1. 运行前先在云安全组放行新 SSH 端口。
2. 保留当前 SSH 会话，直到新端口登录成功。
3. 确保有 VNC / 控制台作为备用入口。
4. UFW 启用后可能影响其他服务端口，请提前确认。
5. Fail2Ban 永久封禁策略较激进，注意误封风险。
6. 系统升级可能引入内核更新，建议在维护窗口执行，并准备好重启。
7. 生产环境建议固定版本标签，而非直接使用 `main` 分支。

## 故障排查

- BBR 状态：`sysctl net.ipv4.tcp_congestion_control`
- 可用算法：`sysctl net.ipv4.tcp_available_congestion_control`
- 监听端口：`ss -lntp`
- SSH 配置：`sshd -t`、`systemctl status ssh.service ssh.socket`
- UFW：`ufw status numbered`
- Fail2Ban：`fail2ban-client status sshd`
- 若无法连接，优先使用云厂商控制台恢复，不要反复运行脚本。

## License

MIT License，详见仓库中的 `LICENSE` 文件。
