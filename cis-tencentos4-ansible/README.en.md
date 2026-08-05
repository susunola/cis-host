# CIS TencentOS Linux 4 Benchmark v1.0.0 — Ansible Playbooks

[English](README.md) | **简体中文**

基于 CIS **TencentOS Linux 4 Benchmark v1.0.0** 的合规扫描与修复 Playbook。

## 一次运行的流程

```
  控制机                     目标机                          磁盘
  ──────                     ──────                          ────

  ansible-playbook
       │
       │  preflight：变量、python3 ≥ 3.6、root
       │  推 4 个文件  ──────────────▶  /tmp/cis-scan/
       │                                cis_engine.py
       │                                rules.json
       │                                guidance.json
       │                                sections.json
       │
       │  python3 cis_engine.py
       │    --mode scan | apply
       │    --profile L1 | L2
       ├────────────────────────────▶   275 条规则
       │                                scan ：只读
       │                                apply：改配置 + 再校验
       │                                      备份到 /var/backups/cis-tencentos4/
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
| **HTML 报告** | 自包含单文件，含主机名 / IP / MAC、合规分、章节分布、可搜索明细表 |
| **CSV 导出** | 平坦化所有检查结果，方便导入 SIEM 或 BI 工具 |
| **集群总览** | 多主机时生成 index 页面汇总各节点状态 |
| **风险分级** | 高风险修复默认跳过，需显式放行 |
| **细粒度过滤** | `--include`、`--exclude`、`--sections`、`--families` |

## 报告内容

报告顶部展示：

- **主机名、IP 地址、MAC 地址**
- 操作系统 / 内核版本 / 架构 / 虚拟化环境
- 网络接口明细（可展开）

下方分 **Level 1** 和 **Level 2** 两张卡片，每张显示：

- 本次 **已修复** 条数（apply 模式）或 **待修复** 条数（scan 模式）
- 合规率进度条（绿=通过 / 红=未通过 / 蓝=人工核查 / 紫=异常）
- 已修复 / 已改待生效 / 修复失败 / 跳过高风险 / 无自动修复 / 本就合规

报告工具栏可按 **结果状态、风险等级（低风险 / 高风险 / 不涉及）、级别、章节** 与关键字筛选；点击任意行展开判定依据与 CIS 整改原文。

## 关键变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `cis_mode` | `scan` | `scan` 或 `apply` |
| `cis_profile` | `L1` | `L1` 或 `L2` |
| `cis_platform` | `server` | `server` / `workstation` / `all` |
| `cis_allow_disruptive` | `false` | 是否允许重启 / 分区变更等高风险修复 |
| `cis_include` | `[]` | 仅运行指定规则 ID 前缀 |
| `cis_exclude` | `[]` | 排除指定规则 |
| `cis_sections` | `[]` | 仅运行 ID 以这些前缀开头的规则 |
| `cis_families` | `[]` | 仅运行这些修复家族的规则 |
| `cis_fail_on_findings` | `false` | 有未通过项时让 play 失败 |
| `cis_min_score` | `0` | 合规分低于此值时失败 |

## 目录结构

```
cis-tencentos4-ansible/
├── ansible.cfg                    # Ansible 配置
├── site.yml                       # 主 playbook（通用入口）
├── scan.yml                       # 扫描模式快捷入口
├── apply.yml                      # 修复模式快捷入口
├── inventory/
│   └── hosts.ini                  # 目标主机清单
├── group_vars/
│   └── all.yml                    # 全局变量覆盖
├── reports/                       # HTML/JSON/CSV 报告输出目录
└── roles/cis_tencentos4/
    ├── defaults/main.yml          # 角色默认变量
    ├── vars/main.yml              # 内部变量
    ├── meta/main.yml              # 元数据
    ├── files/
    │   ├── cis_engine.py          # 合规评估引擎（Python 3）
    │   ├── rules.json             # 规则目录
    │   ├── guidance.json          # 整改建议文本
    │   └── sections.json          # 章节标题
    ├── tasks/
    │   ├── main.yml               # 入口：preflight → run → report → gate
    │   ├── preflight.yml          # 参数校验 + Python 探测 + 权限检查
    │   ├── run.yml                # 部署引擎 → 执行 → 收集结果
    │   ├── report.yml             # 渲染 HTML/JSON/CSV + index
    │   └── gate.yml               # 合规门禁（可选）
    └── templates/
        ├── report.html.j2         # 单主机 HTML 报告模板
        ├── index.html.j2          # 集群总览页模板
        └── findings.csv.j2        # CSV 导出模板
```

## 引擎说明

评估引擎 (`cis_engine.py`) 是一个纯 Python 3 脚本（无第三方依赖），在目标机上以 root 身份运行。它实现了一批 **检查 + 修复家族**，覆盖 CIS 基准中约 **88%** 的自动化判定规则。

引擎输出 JSON 文档，包含：

- 主机信息（hostname / IP / MAC / OS / 内核）
- 按 L1/L2 分组的汇总统计（pass/fail/manual/error/applied 等）
- 每条规则的详细结果（状态、判定依据、修复动作、耗时）

## 注意事项

1. 目标机需要 **Python 3.6+** 和 **root 权限**
2. `apply` 模式会修改系统配置文件（原文件备份至 `/var/backups/cis-tencentos4/`）
3. 涉及重启的修复默认跳过；确认维护窗口后加 `-e cis_allow_disruptive=true`
4. 先在测试环境跑 `scan`，审阅报告后再对生产执行 `apply`
5. 本自动化不能替代人工安全审计
