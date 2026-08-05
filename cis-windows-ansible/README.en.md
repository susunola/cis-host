# CIS Windows Server 2025 Benchmark v2.1.0 — Ansible Playbooks

[English](README.md) | **简体中文**

基于 CIS **Microsoft Windows Server 2025 Benchmark v2.1.0** 的自动化合规扫描与修复 Playbook，属于 [CIS-OS](../) 项目的一部分。

## 一次运行的流程

```
  控制机                     Windows 主机                       磁盘
  ──────                     ───────────                        ────

  ansible-playbook
       │
       │  preflight：变量、PowerShell ≥ 5.1、Administrator
       │  推 4 个文件  ──────────────▶  C:\Windows\Temp\cis-scan\
       │                                cis_engine.ps1
       │                                rules.json
       │                                guidance.json
       │                                sections.json
       │
       │  powershell.exe -File cis_engine.ps1
       │    -Mode scan | apply
       │    -Profile L1 | L2
       ├────────────────────────────▶   30 条规则
       │                                scan ：只读
       │                                apply：改配置 + 再校验
       │                                      备份到 C:\cis-backups\
       │                                   │
       │                                   ▼
       │                              result.json
       ◀────────────────────────────────
       │
       │  渲染 Jinja2  ────────────▶  reports/HOST-L1-scan.html
       │  (report.html.j2)             reports/HOST-L1-apply.html
       │                               reports/index.html（N>1）
       ▼
  open reports/*-L1-scan.html
```

完整生命周期和引擎内部细节见 [根目录 README](../#一次运行的流程)。

## 快速开始

```bash
# 1) 编辑 inventory，填入目标主机
vim inventory/hosts.ini

# 2) L1 扫描（只读，不改任何东西）
ansible-playbook -i inventory/hosts.ini scan.yml

# 3) 查看报告
open reports/*-L1-scan.html

# 4) L1 修复（先看报告确认影响范围）
ansible-playbook -i inventory/hosts.ini apply.yml

# 5) L2 全量扫描 + 修复（含高风险项）
ansible-playbook -i inventory/hosts.ini scan.yml -e cis_profile=L2
ansible-playbook -i inventory/hosts.ini apply.yml -e cis_profile=L2 \
    -e cis_allow_disruptive=true
```

## 功能

| 功能 | 说明 |
|------|------|
| **scan** | 只读评估，不修改目标机任何文件或配置 |
| **apply** | 自动修复未通过规则，修复后重新验证 |
| **L1 / L2 选择** | `cis_profile=L1`（基线防护）或 `cis_profile=L2`（纵深防御）|
| **HTML 报告** | 自包含单文件，含主机名 / IP / OS、合规分、章节分布、可搜索明细表 |
| **CSV 导出** | 平坦化所有检查结果，方便导入 SIEM 或 BI 工具 |
| **集群总览** | 多主机时自动生成 index 页面汇总各节点状态 |
| **风险分级** | 高风险修复默认跳过，需显式放行 |
| **细粒度过滤** | `-Include`、`-Exclude`、`-Sections`、`-Families` |

## 关键变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `cis_mode` | `scan` | `scan` 或 `apply` |
| `cis_profile` | `L1` | `L1` 或 `L2` |
| `cis_platform` | `server` | `server` / `workstation` / `all` |
| `cis_allow_disruptive` | `false` | 是否允许重启 / 服务重启等高风险修复 |
| `cis_include` | `[]` | 仅运行指定规则 ID 前缀 |
| `cis_exclude` | `[]` | 排除指定规则 |
| `cis_sections` | `[]` | 仅运行 ID 以这些前缀开头的规则 |
| `cis_families` | `[]` | 仅运行这些修复家族的规则 |
| `cis_fail_on_findings` | `false` | 有未通过项时让 play 失败 |
| `cis_min_score` | `0` | 合规分低于此值时失败 |

## 目录结构

```
cis-windows-ansible/
├── scan.yml                       # 扫描模式快捷入口
├── apply.yml                      # 修复模式快捷入口
├── inventory/
│   └── hosts.ini                  # 目标主机清单
├── group_vars/
│   └── all.yml                    # 全局变量覆盖
├── reports/                       # HTML/JSON/CSV 报告输出目录
└── roles/cis_windows/
    ├── defaults/main.yml          # 角色默认变量
    ├── vars/main.yml              # 内部变量
    ├── meta/main.yml              # 元数据
    ├── files/
    │   ├── cis_engine.ps1         # 合规评估引擎（PowerShell）
    │   ├── rules.json             # 规则目录
    │   ├── guidance.json          # 整改建议文本
    │   └── sections.json          # 章节标题
    ├── tasks/
    │   ├── main.yml               # 入口：preflight → run → report → gate
    │   ├── preflight.yml          # 参数校验 + PowerShell 探测 + 权限检查
    │   ├── run.yml                # 部署引擎 → 执行 → 收集结果
    │   ├── report.yml             # 渲染 HTML/JSON/CSV + index
    │   └── gate.yml               # 合规门禁（可选）
    └── templates/
        ├── report.html.j2         # 单主机 HTML 报告模板
        ├── index.html.j2          # 集群总览页模板
        └── findings.csv.j2        # CSV 导出模板
```

## 引擎说明

评估引擎 (`cis_engine.ps1`) 是一个单文件 PowerShell 脚本（无第三方依赖），在目标机上以 Administrator 身份通过 WinRM 执行。

引擎输出 JSON 文档，包含：

- 主机信息（hostname / IP / OS）
- 按 L1/L2 分组的汇总统计（pass/fail/manual/error/applied 等）
- 每条规则的详细结果（状态、判定依据、修复动作、耗时）

## 注意事项

1. 目标机需要 **PowerShell 5.1+** 和 **Administrator** 身份（需配置好 WinRM）
2. `apply` 模式会修改注册表 / GPO / 本地策略；原值备份至 `C:\cis-backups\`
3. 涉及重启 / 重启服务的修复默认跳过；确认维护窗口后加 `-e cis_allow_disruptive=true`
4. 先在测试环境跑 `scan`，审阅报告后再对生产执行 `apply`
5. 本自动化不能替代人工安全审计
