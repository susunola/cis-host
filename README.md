# CIS-OS

A collection of Ansible playbooks that implement **CIS security benchmarks** for multiple
Linux distributions, with `scan` and `apply` modes and a generated, professional HTML report.
一组面向多种 Linux 发行版的 Ansible Playbook，实现 **CIS 安全基准**的 `scan` / `apply`
双模式，并生成专业 HTML 报告。

> 中文 / English — 本说明为中英双语。 · This document is bilingual (Chinese / English).

Currently ships two independent, self-contained playbook suites (more OS families — e.g.
RHEL — to be added later under the same layout):
当前包含两套互相独立的 Playbook（后续按同样结构扩展 RHEL 等发行版）:

| Suite 套件 | Benchmark 基准 | Rules 规则数 | Automated 自动化率 |
|-------|-----------|-------|-----------|
| `cis-tencentos3-ansible/` | CIS TencentOS Linux 3 Benchmark v1.0.0 | 322 | ~95% |
| `cis-tencentos4-ansible/` | CIS TencentOS Linux 4 Benchmark v1.0.0 | 275 | ~88% |

Each suite is a standalone Ansible project (its own `inventory/`, `group_vars/`,
`ansible.cfg`, `scan.yml`, `apply.yml`, `site.yml`, and a full `roles/` tree).
每个套件都是独立的 Ansible 工程（自带 `inventory/`、`group_vars/`、`ansible.cfg`、
`scan.yml`、`apply.yml`、`site.yml` 及完整 `roles/` 树）。

## What it does · 功能

- **Scan** (`scan.yml`) — read-only assessment of every selected rule; produces a
  compliance report with a per-host score. · **扫描**：只读评估所选规则，生成含单主机合规分的报告。
- **Apply** (`apply.yml`) — remediates failing rules automatically, then re-verifies
  and reports the new score. · **修复**：自动修复未通过规则并重新验证、回报告。
- **Profile selection** — run against the **L1** or **L2** CIS profile
  (`-e cis_profile=L1|L2`). · **级别选择**：`-e cis_profile=L1|L2`。
- **Disruptive guard** — risky remediations (reboot / service restart) are skipped
  unless `-e cis_allow_disruptive=true`. · **高风险保护**：重启/重服务等默认跳过，需显式放行。
- **HTML report** — after each run, an HTML report is rendered per host showing:
  · **HTML 报告**：每次运行后按主机渲染，展示：
  - Host **name / IP / MAC** at the top · 顶部 **主机名 / IP / MAC**
  - **L1** and **L2** cards showing how many rules were applied (applied / pending /
    failed / skipped) plus a compliance score · **L1 / L2** 卡片：已修复条数（已修复/待生效/失败/跳过）+ 合规分
  - A filterable per-rule findings table with CIS rationale and remediation text · 可筛选的规则明细表（含 CIS 依据与整改原文）
  - A multi-host cluster overview index page · 多主机集群总览 index 页

## Quick start · 快速开始

```bash
# 1. Edit the inventory to point at your TencentOS hosts
#    编辑 inventory，指向你的 TencentOS 主机
vim cis-tencentos3-ansible/inventory/hosts.ini

# 2. L1 scan / L1 扫描
ansible-playbook -i cis-tencentos3-ansible/inventory/hosts.ini \
                 cis-tencentos3-ansible/scan.yml

# 3. L1 apply / L1 修复
ansible-playbook -i cis-tencentos3-ansible/inventory/hosts.ini \
                 cis-tencentos3-ansible/apply.yml

# 4. L2 full + allow disruptive remediations / L2 全量 + 放行高风险
ansible-playbook -i cis-tencentos3-ansible/inventory/hosts.ini \
                 cis-tencentos3-ansible/apply.yml \
                 -e cis_profile=L2 -e cis_allow_disruptive=true
```

Same commands apply under `cis-tencentos4-ansible/` for TencentOS Linux 4.
TencentOS Linux 4 同理，把目录换成 `cis-tencentos4-ansible/` 即可。

## How it works · 工作原理

Each suite ships a small, dependency-free Python assessment engine
(`roles/cis_tencentos{3,4}/files/cis_engine.py`) that is copied to the managed node and
run as a `script:` task. The engine reads a rule catalog (`rules.json`) plus a guidance
bundle (`guidance.json`) and emits a single JSON result document. Ansible then gathers
host facts (hostname / IP / MAC) and renders the Jinja2 HTML report.
每个套件自带一个无依赖的 Python 评估引擎（`cis_engine.py`），以 `script:` 任务推送到目标机
执行；引擎读取规则目录 `rules.json` 与整改建议 `guidance.json`，输出单个 JSON 结果文档。
Ansible 再收集主机事实（hostname / IP / MAC）并渲染 Jinja2 HTML 报告。

The engine classifies each rule into a remediation *family* (kmod, sysctl, file_perm,
svc_disabled, sshd_param, audit_rule, pam_arg, selinux, …) and assigns a risk level:
引擎把每条规则归入一个修复族（kmod、sysctl、file_perm、svc_disabled、sshd_param、
audit_rule、pam_arg、selinux …）并标记风险级别：

- `safe` — idempotent config change, applied by default · 幂等配置变更，默认应用
- `disruptive` — needs reboot / service restart, only with `cis_allow_disruptive=true` · 需重启/重服务，仅显式放行时执行
- `none` — scan-only / manual (e.g. partition layout, bootloader password) · 仅扫描/人工（如分区、引导密码）

## Notes / caveats · 注意事项

- Remediations are applied **in place** on the target host. Review `scan.yml` output
  and use `--check` (the role auto-downgrades `apply` to `scan` under `--check`) before
  running `apply` on production systems.
  修复会**就地**修改目标机。生产环境执行 `apply` 前，先用 `--check`（角色会自动降级为 scan）审阅。
- 6 rule families are intentionally fix-less (require human judgement or are
  reboot/site-specific): `bootloader_password`, `info_only`, `manual`, `partition`,
  `root_access`, `sshd_access`.
  6 个族刻意不做自动修复（需人工判断或重启/特定场景）：`bootloader_password`、`info_only`、
  `manual`、`partition`、`root_access`、`sshd_access`。
- The engine is Linux-targeted (uses `rpm`, `dnf`, `systemctl`, `sshd -T`, `auditctl`,
  `/proc`, …). Run it on a TencentOS Linux 3/4 host.
  引擎面向 Linux（依赖 `rpm`、`dnf`、`systemctl`、`sshd -T`、`auditctl`、`/proc` …），请在 TencentOS Linux 3/4 上运行。

## License · 许可

Benchmark content © Center for Internet Security. Automation in this repository is
provided as-is for operational use.
基准内容 © Center for Internet Security。本仓库中的自动化脚本按现状提供，仅供运维使用。
