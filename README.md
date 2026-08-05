# CIS-OS

[English](README.en.md) | 中文

一组面向多种 Linux 发行版的 Ansible Playbook，基于 **CIS 安全基准** 实现 `scan`（扫描）与 `apply`（修复）双模式，并生成独立的专业 HTML 报告。

> 本仓库会持续扩展：目前包含 TencentOS Linux 3 / 4，后续按相同结构加入 RHEL 等发行版。

## 包含的套件

| 套件 | 基准 | 规则数 | 自动化率 |
|-------|-----------|-------|-----------|
| `cis-tencentos3-ansible/` | CIS TencentOS Linux 3 Benchmark v1.0.0 | 322 | ~95% |
| `cis-tencentos4-ansible/` | CIS TencentOS Linux 4 Benchmark v1.0.0 | 275 | ~88% |

每个套件都是独立的 Ansible 工程（自带 `inventory/`、`group_vars/`、`ansible.cfg`、`scan.yml`、`apply.yml`、`site.yml` 及完整 `roles/` 树）。

## 功能

- **扫描（scan）**：只读评估所选规则，生成含单主机合规分的报告。
- **修复（apply）**：自动修复未通过规则，重新验证并回报告。
- **级别选择**：`-e cis_profile=L1|L2` 选择 L1（基线防护）或 L2（纵深防御）。
- **高风险保护**：涉及重启 / 服务中断的修复默认跳过，需 `-e cis_allow_disruptive=true` 显式放行。
- **HTML 报告**：每次运行后按主机渲染，展示主机名 / IP / MAC、L1/L2 已修复条数、合规分、可筛选的规则明细表，以及多主机集群总览 index 页。报告支持 **中文 / English 一键切换** 与 **按风险等级过滤**。

## 快速开始

```bash
# 1. 编辑 inventory，指向你的 TencentOS 主机
vim cis-tencentos3-ansible/inventory/hosts.ini

# 2. L1 扫描
ansible-playbook -i cis-tencentos3-ansible/inventory/hosts.ini \
                 cis-tencentos3-ansible/scan.yml

# 3. L1 修复
ansible-playbook -i cis-tencentos3-ansible/inventory/hosts.ini \
                 cis-tencentos3-ansible/apply.yml

# 4. L2 全量 + 放行高风险
ansible-playbook -i cis-tencentos3-ansible/inventory/hosts.ini \
                 cis-tencentos3-ansible/apply.yml \
                 -e cis_profile=L2 -e cis_allow_disruptive=true
```

TencentOS Linux 4 同理，把目录换成 `cis-tencentos4-ansible/` 即可。

## 工作原理

每个套件自带一个无依赖的 Python 评估引擎（`cis_engine.py`），以 `script:` 任务推送到目标机执行；引擎读取规则目录 `rules.json` 与整改建议 `guidance.json`，输出单个 JSON 结果文档。Ansible 再收集主机事实（hostname / IP / MAC）并渲染 Jinja2 HTML 报告。

引擎把每条规则归入一个修复族（kmod、sysctl、file_perm、svc_disabled、sshd_param、audit_rule、pam_arg、selinux …）并标记风险级别：

- `safe`：幂等配置变更，默认应用。
- `disruptive`：需重启 / 重服务，仅显式放行时执行。
- `none`：仅扫描 / 人工（如分区、引导密码）。

## 多主机

一次 play 可同时评估多台主机：每台主机生成独立的 HTML 报告，并在末尾自动汇总生成 **集群总览 index 页**，按主机列出合规分、L1/L2 已修复条数，并给出全集群累计统计。单主机报告在评估多台时会显示「返回集群总览」入口。

## 注意事项

- 修复会**就地**修改目标机。生产环境执行 `apply` 前，先用 `--check`（角色会自动降级为 scan）审阅。
- 6 个族刻意不做自动修复（需人工判断或重启 / 特定场景）：`bootloader_password`、`info_only`、`manual`、`partition`、`root_access`、`sshd_access`。
- 引擎面向 Linux（依赖 `rpm`、`dnf`、`systemctl`、`sshd -T`、`auditctl`、`/proc` …），请在 TencentOS Linux 3/4 上运行。

## 许可

基准内容 © Center for Internet Security。本仓库中的自动化脚本按现状提供，仅供运维使用。
