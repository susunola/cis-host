# CIS TencentOS Linux 3 Benchmark v1.0.0 — Ansible Playbooks
# CIS TencentOS Linux 3 Benchmark v1.0.0 — 合规扫描与修复 Playbook

> 中文 / English — 本说明为中英双语。 · This document is bilingual (Chinese / English).

基于 CIS **TencentOS Linux 3 Benchmark v1.0.0** 的自动化合规扫描与修复 Playbook。
Ansible playbooks that implement the **CIS TencentOS Linux 3 Benchmark v1.0.0** for
automated compliance scanning and remediation.

## 快速开始 · Quick Start

```bash
# 1) 编辑 inventory，填入目标主机 / edit inventory with your target hosts
vim inventory/hosts.ini

# 2) L1 扫描（只读，不改任何东西）/ L1 scan (read-only, no changes)
ansible-playbook -i inventory/hosts.ini scan.yml

# 3) 查看报告 / open the report
open reports/*-L1-scan.html

# 4) L1 修复（先看报告确认影响范围）/ L1 apply (review the report first)
ansible-playbook -i inventory/hosts.ini apply.yml

# 5) L2 全量扫描 + 修复（含高风险项）/ L2 full scan + apply (incl. disruptive)
ansible-playbook -i inventory/hosts.ini scan.yml -e cis_profile=L2
ansible-playbook -i inventory/hosts.ini apply.yml -e cis_profile=L2 \
    -e cis_allow_disruptive=true
```

## 功能 · Features

| 功能 Feature | 说明 Description |
|------|------|
| **scan** | 只读评估，不修改目标机任何文件或配置 · Read-only assessment; never modifies the target |
| **apply** | 自动修复未通过规则，修复后重新验证 · Auto-remediates failing rules, then re-verifies |
| **L1 / L2 选择 · Profile** | `cis_profile=L1`（基线防护）或 `cis_profile=L2`（纵深防御）· `L1` (baseline) or `L2` (defense-in-depth) |
| **HTML 报告 · Report** | 自包含单文件，含主机名/IP/MAC、合规分、章节分布、可搜索明细表 · Self-contained file: hostname/IP/MAC, score, chapters, searchable table |
| **CSV 导出 · CSV** | 平坦化所有检查结果，方便导入 SIEM 或 BI 工具 · Flattened findings for SIEM / BI import |
| **集群总览 · Fleet** | 多主机时自动生成 index 页面汇总各节点状态 · Auto index page summarising all hosts |
| **风险分级 · Risk tiers** | 高风险修复默认跳过，需显式放行 · Disruptive fixes skipped unless explicitly allowed |

## 报告内容 · Report Contents

报告顶部展示 · *Top of the report:*

- **主机名、IP 地址、MAC 地址** · Hostname, IP address, MAC address
- 操作系统 / 内核版本 / 架构 / 虚拟化环境 · OS / kernel / arch / virtualization
- 网络接口明细（可展开）· Network interfaces (expandable)

下方分 **Level 1** 和 **Level 2** 两张卡片，每张显示 · *Two cards below, L1 and L2, each shows:*

- 本次 **已修复** 条数（apply 模式）或 **待修复** 条数（scan 模式）· Rules **fixed** (apply) or **to fix** (scan)
- 合规率进度条（绿=通过 / 红=未通过 / 蓝=人工核查 / 紫=异常）· Compliance bar (green=pass red=fail blue=manual purple=error)
- 已修复 / 已改待生效 / 修复失败 / 跳过高风险 / 无自动修复 / 本就合规 · fixed / pending / failed / skipped-disruptive / unsupported / already-compliant

## 关键变量 · Key Variables

| 变量 Variable | 默认值 Default | 说明 Description |
|------|--------|------|
| `cis_mode` | `scan` | `scan` 或 `apply` · `scan` or `apply` |
| `cis_profile` | `L1` | `L1` 或 `L2` · `L1` or `L2` |
| `cis_platform` | `server` | `server` / `workstation` / `all` |
| `cis_allow_disruptive` | `false` | 是否允许重启/分区变更等高风险修复 · Allow reboot/remount etc. |
| `cis_include` | `[]` | 仅运行指定规则 ID 前缀 · Run only matching rule-id prefixes |
| `cis_exclude` | `[]` | 排除指定规则 · Exclude given rules |
| `cis_fail_on_findings` | `false` | 有未通过项时让 play 失败 · Fail the play on findings |
| `cis_min_score` | `0` | 合规分低于此值时失败 · Fail below this score |

## 目录结构 · Directory Layout

```
cis-tencentos3-ansible/
├── ansible.cfg                    # Ansible 配置 / config
├── site.yml                       # 主 playbook（通用入口）/ main entry
├── scan.yml                       # 扫描模式快捷入口 / scan shortcut
├── apply.yml                      # 修复模式快捷入口 / apply shortcut
├── inventory/
│   └── hosts.ini                  # 目标主机清单 / target hosts
├── group_vars/
│   └── all.yml                    # 全局变量覆盖 / global overrides
├── reports/                       # HTML/JSON/CSV 报告输出目录 / output
└── roles/cis_tencentos3/
    ├── defaults/main.yml          # 角色默认变量 / defaults
    ├── vars/main.yml              # 内部变量 / internal vars
    ├── meta/main.yml              # Galaxy 元数据 / metadata
    ├── files/
    │   ├── cis_engine.py          # 合规评估引擎（Python 3）/ engine
    │   ├── rules.json             # 规则目录 / rule catalog
    │   ├── guidance.json          # 整改建议文本 / remediation text
    │   └── sections.json          # 章节标题 / chapter titles
    ├── tasks/
    │   ├── main.yml               # 入口：preflight → run → report → gate
    │   ├── preflight.yml          # 参数校验 + Python 探测 + 权限检查
    │   ├── run.yml                # 部署引擎 → 执行 → 收集结果
    │   ├── report.yml             # 渲染 HTML/JSON/CSV + index
    │   └── gate.yml               # 合规门禁（可选）/ compliance gate
    └── templates/
        ├── report.html.j2         # 单主机 HTML 报告模板 / host report
        ├── index.html.j2          # 集群总览页模板 / fleet overview
        └── findings.csv.j2        # CSV 导出模板 / CSV export
```

## 引擎说明 · Engine Notes

评估引擎 (`cis_engine.py`) 是一个纯 Python 3 脚本（无第三方依赖），在目标机上以 root 身份运行。它实现了 **61 个检查族**和 **55 个自动修复族**，覆盖 CIS 基准中约 **95%** 的自动化判定规则。
The assessment engine (`cis_engine.py`) is a pure-Python 3 script (no third-party deps)
run as root on the target. It implements **61 check families** and **55 auto-remediation
families**, covering about **95%** of the benchmark's automatable rules.

引擎输出 JSON 文档，包含 · *The engine emits a JSON document with:*

- 主机信息（hostname / IP / MAC / OS / 内核）· Host info (hostname / IP / MAC / OS / kernel)
- 按 L1/L2 分组的汇总统计（pass/fail/manual/error/applied 等）· L1/L2 grouped summary stats
- 每条规则的详细结果（状态、判定依据、修复动作、耗时）· Per-rule detail (status, evidence, fix, time)

## 注意事项 · Notes

1. 目标机需要 **Python 3.6+** 和 **root 权限** · Target needs **Python 3.6+** and **root**
2. `apply` 模式会修改系统配置文件（原文件备份至 `/var/backups/cis-tencentos3/`）· `apply` edits configs (backups in `/var/backups/cis-tencentos3/`)
3. 涉及重启的修复默认跳过；确认维护窗口后加 `-e cis_allow_disruptive=true` · Reboot fixes skipped by default; add the flag in a change window
4. 先在测试环境跑 `scan`，审阅报告后再对生产执行 `apply` · Run `scan` in staging and review before `apply` in prod
5. 本自动化不能替代人工安全审计 · This automation does not replace a manual security audit
