# CIS-OS

[English](README.md) | **简体中文**

针对 TencentOS Linux 3、TencentOS Linux 4 与 Windows Server 跑 **CIS** 安全基准的 Ansible Playbook。每个套件有两种模式 —— `scan`（只读）与 `apply`（修复），并按主机生成独立的 HTML 报告。

## 架构

<p align="center">
  <img src="docs/architecture.svg" alt="CIS-OS 架构图" width="960">
</p>

引擎是单文件脚本（Linux 是 Python 3，Windows 是 PowerShell），无第三方依赖。Ansible 只负责文件拷贝、命令执行、报告渲染。

## 一次运行的流程

### scan（只读）

1. `preflight` —— Ansible 校验变量，探测目标机的 Python 3.6+（Windows 是 PowerShell 5.1+），确认 root / Administrator 身份。
2. `push` —— 把 `cis_engine.py`、`rules.json`、`guidance.json`、`sections.json` 推到目标机的 `/tmp/cis-scan/`（Windows 是 `C:\Windows\Temp\cis-scan`）。
3. `run` —— 引擎以 `--mode scan` 启动，遍历规则目录逐条检查，采集判定依据，写出 `result.json`。目标机上的任何东西都不会被修改。
4. `fetch` —— Ansible 把 `result.json` 拉回控制机。
5. `report` —— Jinja2 模板（`report.html.j2`）结合 `result.json` 和主机事实（hostname / IP / MAC / OS / 内核）渲染出 HTML 报告。

### apply（修复）

1、2、4、5 步与 scan 完全相同。区别只在第 3 步：

3. 引擎以 `--mode apply` 启动。对每条未通过且属于已知可修家族的规则，引擎先备份原文件到 `/var/backups/cis-<os>/`，再修改配置，然后重新跑一次检查确认新状态。需要重启或重启服务的规则默认跳过，除非显式传入 `cis_allow_disruptive=true`。

报告里会同时展示 **修改前**（如果你事先跑过 scan）和 **修改后** 的状态，并给出 delta。如果 apply 之后跑 scan 发现新引入的失败项，报告会单列一个 "regressions" 区块。

## 套件

| 套件 | 基准 | 引擎 | 规则数 |
|------|------|------|--------|
| `cis-tencentos3-ansible/` | CIS TencentOS Linux 3 v1.0.0 | Python 3 | 322 |
| `cis-tencentos4-ansible/` | CIS TencentOS Linux 4 v1.0.0 | Python 3 | 275 |
| `cis-windows-ansible/`    | CIS Windows Server 2025 v2.1.0 | PowerShell | 154 |

每个套件都是独立的 Ansible 工程，自带 inventory、group_vars、`scan.yml`、`apply.yml`、role 树、模板。

## 快速开始

```bash
# 1. 编辑 inventory，指向目标主机
vim cis-tencentos3-ansible/inventory/hosts.ini

# 2. L1 scan（只读）
ansible-playbook -i cis-tencentos3-ansible/inventory/hosts.ini \
                 cis-tencentos3-ansible/scan.yml

# 3. 看报告
open cis-tencentos3-ansible/reports/*-L1-scan.html

# 4. L1 apply（先看报告确认影响范围）
ansible-playbook -i cis-tencentos3-ansible/inventory/hosts.ini \
                 cis-tencentos3-ansible/apply.yml

# 5. L2 全量 + 放行高风险
ansible-playbook -i cis-tencentos3-ansible/inventory/hosts.ini \
                 cis-tencentos3-ansible/apply.yml \
                 -e cis_profile=L2 -e cis_allow_disruptive=true
```

TOS 4 和 Windows 把目录名换掉即可。

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

通过 Ansible 走的时候，对应变量名见各套件 README 的「关键变量」一节。

## 目录结构

```
CIS-OS/
├── README.md                       # 英文（GitHub 默认）
├── README.zh.md                    # 中文
├── cis-tencentos3-ansible/         # TOS 3 套件
│   ├── ansible.cfg
│   ├── scan.yml | apply.yml | site.yml
│   ├── inventory/  group_vars/
│   ├── reports/                    # HTML / JSON / CSV 输出
│   └── roles/cis_tencentos3/
│       ├── files/   cis_engine.py, rules.json, guidance.json, sections.json
│       ├── tasks/   preflight, run, report, gate
│       └── templates/  report.html.j2, index.html.j2, findings.csv.j2
├── cis-tencentos4-ansible/         # TOS 4 套件（结构同上）
└── cis-windows-ansible/            # Windows 套件（PowerShell 引擎）
```

## 多主机

一次 play 把 inventory 里的所有主机都跑一遍。每台主机生成独立的 `reports/HOST-L1-scan.html`。当主机数大于 1 时，role 会额外渲染 `reports/index.html` —— 一个集群总览页，列出每台节点的合规分、通过/未通过计数，并附返回单主机报告的链接。

## 注意事项

- `apply` 会就地修改配置文件。原文件备份在 `/var/backups/cis-<os>/`。
- 标记为 `disruptive` 的规则（重启、重新挂载、重启服务）默认跳过，需要传 `-e cis_allow_disruptive=true` 放行。请在维护窗口跑。
- 6 个家族刻意不做自动修复 —— 需要人工判断或与具体环境相关：`bootloader_password`、`info_only`、`manual`、`partition`、`root_access`、`sshd_access`。引擎会报告这些条目，但不修改任何东西。
- Linux 引擎依赖 `rpm`、`dnf`、`systemctl`、`sshd -T`、`auditctl`、`/proc`，目标机是 TencentOS Linux 3 / 4。Windows 引擎目标机是 Server 2019 / 2022。
- 生产环境执行 `apply` 前，先在测试环境跑 `scan`，审阅报告，再上 `apply`。

## 许可

基准内容版权归 Center for Internet Security 所有。本仓库中的自动化脚本按现状提供，仅供运维使用。
