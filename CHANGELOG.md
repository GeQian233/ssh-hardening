# Changelog

## V5.1

- 增加 Ubuntu 24.04+ / Debian 12+ 发行版及版本检查。
- 自动通过当前 APT 源安装/升级必要依赖。
- 检查 systemd、OpenSSH、UFW、Fail2Ban 版本。
- 检查 systemd socket activation 与 iptables/nftables 后端。
- 预检不满足要求时停止，不进入 SSH/UFW/Fail2Ban 配置修改阶段。
- 保留 SSH 公钥认证、端口迁移、UFW、Fail2Ban 和配置回滚功能。

## 发布说明

V5.1 当前尚未完成 Ubuntu 24.04、Debian 12/13 的独立实机测试。请在发布稳定版前补充这些系统的测试结果。
