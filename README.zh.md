# SecX Automation Suite

**Compliance Baseline as Code | Hardening & Drift Automation**

[English](README.md) | **简体中文** | [日本語](README.ja.md) | [ภาษาไทย](README.th.md)

针对 10 种主流 Linux 发行版及 4 个 Windows Server 版本跑 **CIS** 安全基准的 Ansible Playbook 与本地 CLI。每个套件有两种模式 —— `scan`（只读）与 `apply`（修复），按主机生成独立的交互式 HTML 报告，并支持结构化审计日志。

**支持平台：** RHEL 8/9/10 · TencentOS 3/4 · SLES 15/16 · Ubuntu 20.04/22.04/24.04 LTS · Windows Server 2016/2019/2022/2025

## 架构

<p align="center">
  <img src="docs/architecture.svg" alt="SecX Automation Suite 架构图" width="800">
</p>

引擎是单文件脚本（Linux 为 Python 3，Windows 为 PowerShell），无第三方依赖。Ansible 只负责文件拷贝、命令执行、报告渲染。每个引擎产出 `result.json`（结构化结果）和可选的 `audit.log`（JSON-lines 审计日志），便于合规审查与 SIEM 接入。

## 一次运行的流程

### scan（只读）

1. `preflight` —— Ansible 校验变量，探测目标机的 Python 3.6+（Windows 为 PowerShell 5.1+），确认 root / Administrator 身份。
2. `push` —— 把 `cis_engine.py`、`rules.json`、`guidance.json`、`sections.json` 推到目标机的 `/tmp/cis-scan/`（Windows 为 `C:\Windows\Temp\cis-scan`）。
3. `run` —— 引擎以 `--mode scan` 启动，遍历规则目录逐条检查，采集判定依据，写出 `result.json`。目标机上的任何东西都不会被修改。
4. `fetch` —— Ansible 把 `result.json`（若启用审计，还包括 `audit.log`）拉回控制机。
5. `report` —— Jinja2 模板（`report.html.j2`）结合 `result.json` 和主机事实（hostname / IP / MAC / OS / 内核）渲染出交互式 HTML 报告。

### apply（修复）

1、2、4、5 步与 scan 完全相同。区别只在第 3 步：

3. 引擎以 `--mode apply` 启动。对每条未通过且属于已知可修家族的规则，引擎先备份原文件到 `/var/backups/cis-<os>/`，再修改配置，然后重新跑一次检查确认新状态。需要重启或重启服务的规则默认跳过，除非显式传入 `cis_allow_disruptive=true`。启用审计日志时，每一步操作都会被记录。

报告里会同时展示 **修改前**（如果你事先跑过 scan）和 **修改后** 的状态，并给出 delta。如果 apply 之后跑 scan 发现新引入的失败项，报告会单列一个 "regressions" 区块。

## 套件

| 套件 | 基准 | 引擎 | 规则数 |
|------|------|------|--------|
| `cis-tencentos3-ansible/` | CIS TencentOS Linux 3 v1.0.0 | Python 3 | 322 |
| `cis-tencentos4-ansible/` | CIS TencentOS Linux 4 v1.0.0 | Python 3 | 275 |
| `cis-rhel8-ansible/` | CIS Red Hat Enterprise Linux 8 v4.0.0 | Python 3 | 322 |
| `cis-rhel9-ansible/` | CIS Red Hat Enterprise Linux 9 v2.0.0 | Python 3 | 297 |
| `cis-rhel10-ansible/` | CIS Red Hat Enterprise Linux 10 v1.0.1 | Python 3 | 328 |
| `cis-sles15-ansible/` | CIS SLES 15 v2.0.1 | Python 3 | 286 |
| `cis-sles16-ansible/` | CIS SLES 16 v1.0.0 | Python 3 | 336 |
| `cis-ubuntu2004-ansible/` | CIS Ubuntu 20.04 LTS v3.0.0 | Python 3 | 312 |
| `cis-ubuntu2204-ansible/` | CIS Ubuntu 22.04 LTS v3.0.0 | Python 3 | 306 |
| `cis-ubuntu2404-ansible/` | CIS Ubuntu 24.04 LTS v2.0.0 | Python 3 | 332 |
| `cis-win2016-ansible/` | CIS Microsoft Windows Server 2016 v3.0.0 | PowerShell | 337 |
| `cis-win2019-ansible/` | CIS Microsoft Windows Server 2019 v3.0.0 | PowerShell | 338 |
| `cis-win2022-ansible/` | CIS Microsoft Windows Server 2022 v3.0.0 | PowerShell | 342 |
| `cis-win2025-ansible/` | CIS Microsoft Windows Server 2025 v2.1.0 | PowerShell | 360 |

每个套件都是独立的 Ansible 工程，自带 inventory、group_vars、`scan.yml`、`apply.yml`、role 树、模板。

## 审计日志

当设置 `--audit-log` 时，引擎会在每条规则执行后向指定文件写入一行 JSON，生成结构化、追加安全的审计追踪。每条日志包含：

| 字段 | 说明 |
|------|------|
| `ts` | ISO-8601 UTC 时间戳（毫秒精度） |
| `host` | 目标主机名 |
| `version` | 引擎版本号 |
| `mode` | `scan` 或 `apply` |
| `profile` | `L1` 或 `L2` |
| `rule` | CIS 规则编号（如 `1.1.1.1`） |
| `title` | 规则名称 |
| `status` | `pass`、`fail`、`manual`、`error`、`notapplicable` |
| `apply_status` | `applied`、`already`、`skipped_disruptive`、`failed`、`n/a` |
| `detail` | 取证依据或修复摘要（截断至 200 字符） |
| `duration_ms` | 执行耗时（毫秒） |

**CLI 用法：**

```bash
python3 cis_cli.py scan --os rhel9 --audit-log output/audit-$(hostname).log
```

**Ansible 用法：** 在 playbook 命令行添加 `-e cis_audit_log=/var/log/cis-audit.log`。

审计日志为换行分隔的 JSON 格式，与日志聚合器、SIEM 平台、合规审计工具兼容。

## 快速开始

### 本地 CLI（推荐）

```bash
# L1 scan（只读）
python3 cis_cli.py scan --os rhel9 --profile L1 --output output/

# L1 apply（修复）
python3 cis_cli.py apply --os ubuntu2204 --profile L1 --output output/

# L2 全量 + 放行高风险规则 + 审计日志
python3 cis_cli.py apply --os tencentos4 --profile L2 --allow-disruptive \
  --audit-log output/audit.log --output output/

# 只跑部分规则
python3 cis_cli.py scan --os sles15 --include "1.1.1,1.1.2,5.2" --output output/
```

`--os` 取值：`tencentos3` `tencentos4` · `rhel8` `rhel9` `rhel10` · `sles15` `sles16` · `ubuntu2004` `ubuntu2204` `ubuntu2404` · `win2016` `win2019` `win2022` `win2025`

### 通过 Ansible

```bash
ansible-playbook -i cis-rhel9-ansible/inventory/hosts.ini \
                 cis-rhel9-ansible/scan.yml

ansible-playbook -i cis-rhel9-ansible/inventory/hosts.ini \
                 cis-rhel9-ansible/apply.yml \
                 -e cis_profile=L2 -e cis_allow_disruptive=true
```

## 细粒度执行

引擎和 wrapper 共用同一套过滤项：

| 参数 | 作用 |
|------|------|
| `--mode scan` / `--mode apply` | 只读检查 / 修复 |
| `--profile L1` / `--profile L2` | 基线 / 纵深防御 |
| `--include 1.1.1,1.1.2,5.2` | 只跑这些规则 |
| `--exclude 1.5,1.6` | 跳过这些规则 |
| `--sections 1,5` | 只跑 ID 以这些前缀开头的规则 |
| `--families sysctl,kmod` | 只跑这些修复家族的规则 |
| `--audit-log audit.log` | 写入结构化审计追踪 |

通过 Ansible 走的时候，对应变量名见各套件 README 的「关键变量」一节。

## 目录结构

```
secx/
├── README.md                       # 英文（GitHub 默认）
├── README.zh.md                    # 中文
├── cis_cli.py                      # 本地 CLI（--os 一键切换）
├── docs/architecture.svg           # 架构图
├── cis-tencentos3-ansible/         # TencentOS 3
├── cis-tencentos4-ansible/         # TencentOS 4
├── cis-rhel8-ansible/              # RHEL 8
├── cis-rhel9-ansible/              # RHEL 9
├── cis-rhel10-ansible/             # RHEL 10
├── cis-sles15-ansible/             # SLES 15
├── cis-sles16-ansible/             # SLES 16
├── cis-ubuntu2004-ansible/         # Ubuntu 20.04 LTS
├── cis-ubuntu2204-ansible/         # Ubuntu 22.04 LTS
├── cis-ubuntu2404-ansible/         # Ubuntu 24.04 LTS
├── cis-win2016-ansible/            # Windows Server 2016
├── cis-win2019-ansible/            # Windows Server 2019
├── cis-win2022-ansible/            # Windows Server 2022
└── cis-win2025-ansible/            # Windows Server 2025
    ├── ansible.cfg
    ├── scan.yml | apply.yml | site.yml
    ├── inventory/  group_vars/
    ├── reports/                    # HTML / JSON / CSV / 审计输出
    └── roles/cis_<os>/
        ├── files/   engine, rules.json, guidance.json, sections.json
        ├── tasks/   preflight, run, report, gate
        └── templates/  report.html.j2, index.html.j2, findings.csv.j2
```

## 报告

每次执行产出两种不同用途的 HTML 报告。两者都是静态、自包含、可打印、可切换主题（明 / 暗）的单文件。共用一套 Jinja2 + 原生 JS 技术栈，不依赖任何第三方 CDN，**完全离线可用**。

| 报告 | 模板 | 输出文件名 | 触发条件 |
|------|------|------------|----------|
| **单主机报告** | `templates/report.html.j2` | `HOST-PROFILE-mode-TIMESTAMP.html` | 每次执行（scan / apply 都生成） |
| **集群索引** | `templates/index.html.j2` | `index-TIMESTAMP.html` | inventory 中主机数 > 1，或显式 `-e cis_report_index=true` |

另有 `findings.csv.j2` 模板可输出 Excel / Google Sheets 友好的 CSV，用 `cis_report_csv=true` 开启。

### 单主机报告

单台主机的完整合规画像。任何 scan 或 apply 的默认交付物。

- **评分横幅** —— 总通过率，配色按分数段（≥90 绿、≥70 琥珀、其余红）
- **系统信息** —— 主机名、IPv4、MAC、OS、内核、架构、虚拟化类型、运行时长
- **检查项表格** —— 每条规则的状态、家族、级别、证据、修复提示、基准页码
- **筛选器** —— 按状态（通过 / 失败 / 人工 / 错误 / 不适用）、家族、级别、章节筛选；筛选状态写入 `localStorage` 持久化
- **前后对比** —— apply 模式下，pre-scan 与 post-scan 差异内嵌展示，回归项（修复前通过、修复后失败）单独高亮

### 集群索引

面向多主机合规运维的仪表板。

- **集群总分** —— 整批主机的汇总通过率
- **6 张统计卡** —— 待修复、L1 已修复、L2 已修复、需人工、修复失败、主机数
- **主机表** —— 每台主机一行：分数条、通过 / 失败 pill、已修复计数（含待重启警告）、直达单主机报告的链接
- **下钻** —— 主机行直接跳转到该次执行的对应单主机报告

集群索引只在多主机场景下有意义。单主机执行想强制生成时，加 `-e cis_report_index=true`。

## 多主机

一次 play 把 inventory 里的所有主机都跑一遍。每台主机生成独立的 `reports/HOST-L1-scan.html`。当主机数大于 1 时，role 会额外渲染 `reports/index.html` —— 一个集群总览页，列出每台节点的合规分、通过/未通过计数，并附返回单主机报告的链接。

## 注意事项

- `apply` 会就地修改配置文件。原文件备份在 `/var/backups/cis-<os>/`。
- 标记为 `disruptive` 的规则（重启、重新挂载、重启服务）默认跳过，需要传 `-e cis_allow_disruptive=true` 放行。请在维护窗口跑。
- 6 个家族刻意不做自动修复 —— 需要人工判断或与具体环境相关：`bootloader_password`、`info_only`、`manual`、`partition`、`root_access`、`sshd_access`。引擎会报告这些条目，但不修改任何东西。
- Linux 引擎依赖 `rpm`/`dpkg`、`systemctl`、`sshd -T`、`auditctl`、`/proc`，覆盖 RHEL/Debian/SUSE 系。Windows 引擎目标机是 Server 2016 / 2019 / 2022 / 2025。
- 生产环境执行 `apply` 前，先在测试环境跑 `scan`，审阅报告，再上 `apply`。

## 许可

基准内容版权归 Center for Internet Security 所有。本仓库中的自动化脚本按现状提供，仅供运维使用。
