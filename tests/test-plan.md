# CIS-OS 测试用例设计（真实 Ansible 模拟版）

> 模拟运维从"首次评估 → 干跑评审 → 分批灰度 → 全量部署 → 审计交付"的完整流程。

---

## Phase 1: 发现与验证

| ID | 操作 | 验证点 |
|----|------|--------|
| 1.1 | `ansible-playbook scan.yml/apply.yml/site.yml --syntax-check` | 三个 playbook 均通过语法检查 |
| 1.2 | `--list-tasks` | 输出任务列表 > 5 项（preflight/run/report/gate） |
| 1.3 | `--list-tags` | 含 [cis] [always] [scan] [report] [gate] |
| 1.4 | `--list-hosts` | 包含 tencentos3 或 localhost |
| 1.5 | `ansible -m setup` | 返回 distribution/kernel/arch 等 facts |
| 1.6 | `--tags cis,always --skip-tags scan,report,gate` | preflight 独立运行，benchmark 信息输出 |
| 1.7 | `--skip-tags report,gate` | scan 跳过报告生成和门控 |
| 1.8 | `--tags scan --skip-tags always,report,gate` | 仅 engine 执行阶段（always tag 可能仍触发 preflight） |

## Phase 2: 干跑评估

| ID | 操作 | 验证点 |
|----|------|--------|
| 2.1 | `scan.yml --check -e 'cis_profile=L1'` | --check 模式扫描完成 |
| 2.2 | `apply.yml --check` | **自动降解为 scan**，不执行任何修复 |
| 2.3 | `apply.yml --check --diff` | 降解 + diff 输出（show changes without making them） |
| 2.4 | `scan.yml -v` | verbose 输出含 TASK/ok= |
| 2.5 | `scan.yml -vvv` | 极详细输出正常 |

## Phase 3: 基线扫描

| ID | 操作 | 验证点 |
|----|------|--------|
| 3.1 | L1 scan（preflight + run + report + gate） | 完成，记录 baseline score |
| 3.2 | L2 scan | 完成，对比 L1 分数 |
| 3.3 | L2 score ≤ L1 score | L2 更严格的合规要求 |
| 3.4 | 报告使用 gather_facts 采集的主机信息 | `report.html` 含 OS/kernel/arch 等事实 |

## Phase 4: 增量加固

| ID | 操作 | 系统验证（不只是引擎输出） |
|----|------|---------------------------|
| 4.1 | `apply.yml -e 'cis_families=["kmod"]'` | `/etc/modprobe.d/cis-*.conf` 文件存在 |
| 4.2 | `apply.yml -e 'cis_families=["sysctl"]'` | `sysctl -n net.ipv4.ip_forward` = 0 |
| 4.3 | `apply.yml -e 'cis_families=["svc_disabled","svc_enabled"]'` | `systemctl is-enabled autofs` = disabled |
| 4.4 | `apply.yml -e 'cis_families=["sshd_param","sshd_config_perm"]'` | `/etc/ssh/sshd_config.d/60-cis-hardening.conf` 存在 |
| 4.5 | `apply.yml -e 'cis_families=["audit_perm","audit_rule","audit_privileged"]'` | `/etc/audit/rules.d/` 目录存在 |

## Phase 5: 全量 Apply

| ID | 操作 | 验证点 |
|----|------|--------|
| 5.1 | L1 apply --diff | diff 输出正常，无崩溃 |
| 5.2 | 回扫验证 | post-apply score > baseline score |
| 5.3 | L2 apply | 完成 |
| 5.4 | `apply.yml -e 'cis_serial="1"'` | 逐台（localhost 场景等价于默认行为） |
| 5.5 | `apply.yml -e 'cis_allow_disruptive=true'` | disruptive 规则被修复，applied 计数明显增加 |

## Phase 6: Apply 后系统级验证

| ID | 验证 |
|----|------|
| 6.1 | rescan 完成 |
| 6.2 | result.json 结构完整（results/score/summary/host/changed_files） |
| 6.3 | result.json 无重复 rule ID |
| 6.4 | spot-check 实际系统状态：kmod 黑名单文件、sysctl 持久化文件、sshd drop-in、selinux config |
| 6.5 | changed_files 非空（证明 apply 确实修改了文件） |

## Phase 7: 报告验证

| ID | 验证点 |
|----|--------|
| 7.1 | report.html 生成 |
| 7.2 | result.json 始终存在 |
| 7.3 | CSV 生成（显式启用 cis_report_csv=true） |
| 7.4 | index.html fleet index 生成 |
| 7.5 | HTML 良构（`</html>` 闭合） |
| 7.6 | CSV 无公式注入（无 `= + - @` 前缀行） |

## Phase 8: 合规门控

| ID | 操作 | 预期 |
|----|------|------|
| 8.1 | `cis_fail_on_findings=true` | 有 FAIL 时 playbook 非零退出 |
| 8.2 | `cis_min_score=100` | score < 100 时 playbook 失败 |

## Phase 9: 错误恢复与边界

| ID | 场景 | 预期 |
|----|------|------|
| 9.1 | `cis_profile=L3` | 检测到无效 profile |
| 9.2 | `cis_mode=repair` | 检测到无效 mode |
| 9.3 | 非 root apply | 被拦截（require root/become） |
| 9.4 | `--start-at-task` 断点续跑 | 从指定 task 正常恢复 |
| 9.5 | `cis_engine_timeout=1` | 1 秒超时触发 |

## Phase 10: 幂等与回退

| ID | 验证 |
|----|------|
| 10.1 | 连续 apply 两次：第二次 applied 计数 ≤ 第一次 |
| 10.2 | `apply.yml --check` 不修改系统（降解为 scan） |
| 10.3 | 最终 scan score 稳定，无回退 |
