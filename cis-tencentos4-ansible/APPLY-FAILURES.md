# TOS4 L1 Apply 失败项修复指南

以 `VM-0-9-tencentos`（TencentOS Server 4.4, kernel 6.6.117）L1 apply 报告为基准，覆盖 19 条 Failure 的根因分析、分类与逐条修复命令。

---

## ① 重启后生效（5 条）—— 配置已写入磁盘，reboot 后变为 Pass

| 编号 | 规则 | 已写入的配置 | 重启后效果 |
|---|---|---|---|
| 1.1.1.4 | usb-storage 禁用 | `/etc/modprobe.d/cis-usb-storage.conf` | 模块不再加载 |
| 1.6.3 | ptrace_scope 限制 | `/etc/sysctl.d/60-cis-hardening.conf` — `kernel.yama.ptrace_scope=1` | 运行时值已生效，重启后保持（实际已 OK，标记 Pending 是保守策略） |
| 1.7.1.4 | SELinux mode | `/etc/selinux/config` — `SELINUX=enforcing` | 当前运行时 `Disabled`，重启后进入 enforcing（需 relabel） |
| 3.4.4.1.1 | iptables 安装 | `dnf install iptables` 已完成 | iptables 包已安装，重启后服务就绪 |
| 5.6.1.4 | 不活跃账户锁定 | `useradd -D -f 30` + `chage --inactive 30` 对所有密码用户已执行 | 所有密码账户 inactivity 已设为 30 天 |

**操作**：`reboot`，无需额外命令。

---

## ② 高风险自动跳过 —— 需加 `cis_allow_disruptive: true` 或手动执行

引擎在 apply 时默认跳过 `risk=disruptive` 的规则。如需自动执行，在 `group_vars/all.yml` 中加入：

```yaml
cis_allow_disruptive: true
```

或逐条手动执行：

| 编号 | 规则 | 手动执行命令 | 风险提示 |
|---|---|---|---|
| 1.1.8.2 | `/dev/shm` 加 `noexec` | `mount -o remount,noexec /dev/shm` 并编辑 `/etc/fstab` 在 `/dev/shm` 行的 options 里加 `noexec` | 少数依赖从 `/dev/shm` 执行二进制文件的应用（如某些 JIT 运行时）可能受影响 |
| 1.7.1.8 | 卸载 mcstrans | `dnf -y remove mcstrans` | 只影响 SELinux MCS 标签翻译，多数场景不需要 |
| 3.4.3.7 | 启用 nftables 服务 | `systemctl unmask nftables && systemctl --now enable nftables` | ⚠️ 与 3.4.4.1.2（卸载 nftables）互斥，需先明确防火墙策略 |
| 3.4.4.1.2 | 卸载 nftables | `dnf -y remove nftables` | ⚠️ 与 3.4.3.7（启用 nftables）互斥，二选一 |
| 3.4.4.1.3 | 停止 firewalld | `systemctl stop firewalld && systemctl disable firewalld && systemctl mask firewalld` | ⚠️ 确保已有替代防火墙（iptables 或 nftables）后再停 |
| 5.2.10 | 禁用 SSH root 登录 | 在 `/etc/ssh/sshd_config.d/60-cis-hardening.conf` 中写入 `PermitRootLogin no`，然后 `systemctl reload sshd` | ⚠️ 必须确保有其他 sudo 用户能登录 |
| 5.4.3 | authselect 启用 faillock | `authselect enable-feature with-faillock && authselect apply-changes` | 修改 PAM 配置，建议开第二个 SSH 会话做保险 |
| 6.1.13 | 清除全局可写文件 | `find / -xdev -type f -perm -0002 -exec chmod o-w {} +` | 本次发现 `/etc/uuid`、`/usr/local/qcloud/...` 等云 agent 文件，建议逐一确认后批量改 |

### nftables 冲突说明

3.4.3.7 要求"nftables 服务启用"但 3.4.4.1.2 要求"nftables 未安装"——这是两个不同 CIS 章节的独立要求。实际环境只能二选一。这台机器装了 nftables 但服务未启用，需确定防火墙策略后统一处理。

---

## ③ 磁盘分区 —— 无法自动执行

| 编号 | 规则 | 状态 | 原因 |
|---|---|---|---|
| 1.1.2.1 | `/tmp` 独立分区 | No auto-fix | `/tmp` 没有单独分区/文件系统 |

### 方案 A：tmpfs（推荐，无需额外磁盘空间）

```bash
echo 'tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0' >> /etc/fstab
mount /tmp
```

### 方案 B：新建物理分区

需要空闲磁盘空间，创建新分区并挂载到 `/tmp`。

---

## ④ 自修复失败：1.4.2 文件系统完整性检查

**根因**：TOS4 的 `aide` RPM 可能不提供 `aidecheck.timer` 这个 systemd unit（这是 RHEL 9 的做法，TOS4 打包方式不同）。

```bash
# 1. 确认 aide 是否已安装
rpm -q aide || dnf -y install aide

# 2. 检查是否有 timer unit
systemctl list-unit-files | grep aide

# 3. 如果没有，手动创建
cat > /etc/systemd/system/aidecheck.timer << 'EOF'
[Unit]
Description=Daily AIDE check

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

cat > /etc/systemd/system/aidecheck.service << 'EOF'
[Unit]
Description=AIDE file integrity check

[Service]
Type=oneshot
ExecStart=/usr/sbin/aide --check
EOF

systemctl daemon-reload
systemctl enable --now aidecheck.timer
```

---

## ⑤ 其他真正失败（8 条）—— 逐条手动修复

### 5.5.3 密码复用限制（Failed）

`pam_pwhistory.so` 未出现在 PAM 栈中，引擎无法设置 `remember=5`。

```bash
# 方案 A：走 authselect（推荐）
authselect enable-feature with-pwhistory
authselect apply-changes

# 方案 B：手动编辑
# 在 /etc/pam.d/system-auth 和 /etc/pam.d/password-auth 的 password 段开头加：
# password  required  pam_pwhistory.so  remember=5  use_authtok
```

### 6.1.14 / 6.1.15 无主/无组文件

21 个文件/目录（均来自 `/usr/local/qcloud/stargate/`）属于无效 UID/GID——腾讯云 agent 残留。

```bash
# 查看全部清单
find /usr/local/qcloud/stargate -nouser -o -nogroup 2>/dev/null

# 方案 A：如果不需要 stargate，直接删除
rm -rf /usr/local/qcloud/stargate

# 方案 B：如果需要保留，归给 root
find /usr/local/qcloud/stargate -nouser -exec chown root:root {} + 2>/dev/null
find /usr/local/qcloud/stargate -nogroup -exec chown :root {} + 2>/dev/null
```

### 6.2.2 root PATH 完整性（Failed）

`/root/.local/bin` 和 `/root/bin` 在 root 的 PATH 中但目录不存在。

```bash
# 方案 A：创建缺失目录
mkdir -p /root/.local/bin /root/bin
chmod 700 /root/.local/bin /root/bin

# 方案 B：从 .bashrc / .bash_profile 中删除不存在的目录引用
```

---

## 修复优先级建议

1. **reboot** → 5 条 Pending 变 Pass
2. **1.4.2（aide 定时器）** → 创建 service + timer
3. **5.5.3（密码复用）** → `authselect enable-feature with-pwhistory`
4. **6.1.14/15（无主文件）** → 清理或重新分配 owner
5. **6.2.2（root PATH）** → 创建目录或清理 PATH
6. **高风险项** → 按需逐条评估，确认后加 `cis_allow_disruptive: true` 或手动执行
7. **1.1.2.1（/tmp 分区）** → 运维决定分区方案
