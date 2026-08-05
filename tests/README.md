# CIS-OS 测试套件

在 TencentOS 3 上模拟真实 Ansible 运维流程，10 个 Phase，60+ 检查点。

## 快速开始

```bash
# 1. 创建实例
export TENCENT_SECRET_ID="AKID..." TENCENT_SECRET_KEY="..."
cd tests/provision && bash tccli-create.sh

# 2. 初始化
cd .. && bash bootstrap.sh <公网IP>

# 3. 在目标机器上执行测试
ssh root@<公网IP>
cd /opt/cis-os && bash tests/run-tests.sh

# 4. 销毁
cd tests/provision && bash tccli-destroy.sh <instance-id>
```

## 测试 Phase 说明

| Phase | 内容 | 检查点 | 模拟场景 |
|-------|------|--------|---------|
| 1 | 发现与验证 | syntax-check, list-tasks, list-tags, gather facts, tags 控制 | 运维首次接触项目 |
| 2 | 干跑评估 | --check --diff, -v/-vvv, apply --check 降解 | 上线前安全评审 |
| 3 | 基线扫描 | L1/L2 scan, 分数对比, facts 注入报告 | 建立合规基线 |
| 4 | 增量加固 | 按 family/section 逐步 apply, 每步验证系统状态 | 分批灰度上线 |
| 5 | 全量 Apply | --diff, serial=1, disruptive | 生产全量部署 |
| 6 | 系统级验证 | rescan + 文件/服务/内核实际状态 spot-check | 不只看引擎输出 |
| 7 | 报告验证 | HTML/JSON/CSV/fleet index 生成与内容校验 | 合规审计交付物 |
| 8 | 合规门控 | fail_on_findings, min_score | CI/CD 流水线阻断 |
| 9 | 错误恢复 | 无效输入, --start-at-task 断点续跑, 超时 | 故障演练 |
| 10 | 幂等回退 | 重复 apply 无变化, --check 不修改系统 | 运维安全兜底 |

## 与之前版本的关键区别

**之前**（exit-code 检查）：
```
ansible-playbook scan.yml → grep 'failed=0' → PASS/FAIL
```

**现在**（真实运维模拟）：
```
1. --syntax-check + --list-tasks + --list-tags + gather facts
2. --check --diff 干跑
3. 基线 scan
4. 按 family 增量 apply → 验证实际系统状态（文件/服务/sysctl）
5. 全量 apply --diff, serial=1
6. 系统级 spot-check（不只看 engine 输出）
7. 报告内容校验（HTML 结构/CSV 防注入）
8. 门控测试
9. --start-at-task 断点恢复
10. 幂等验证
```
