# Judgment Engine

研判引擎以 LLM 为调查与解释核心，通过结构化证据查询、确定性计算和结论校验形成可审计的 `JudgmentResult`。

## 文档

- [requirements.md](requirements.md)
- [design.md](design.md)
- [evidence-model.md](evidence-model.md)
- [tool-contract.md](tool-contract.md)
- [verdict-policy.md](verdict-policy.md)
- [verification.md](verification.md)
- [scenarios/](scenarios/common.md)

## 当前状态

当前 Python 原型已经实现案件初始化、Planner、Evidence/Analysis Tool、Policy、Coverage、确定性 Analyzer、场景化 Verdict 和报告。主要缺口是生产数据接入、状态持久化、场景插件化和线上运行治理。

运行时调查知识位于 [`investigation_skills/linux-unknown-file/SKILL.md`](../../../investigation_skills/linux-unknown-file/SKILL.md)，保持原路径。
