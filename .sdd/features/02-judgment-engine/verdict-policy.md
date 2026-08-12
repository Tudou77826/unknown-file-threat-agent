# Verdict Policy

## 结论等级

建议保留：`confirmed_malicious`、`likely_malicious`、`suspicious`、`insufficient_evidence`、`likely_benign` 和 `benign`。

## 通用门槛

- 恶意结论需要证明文件执行或与目标行为存在可靠归因关系。
- 单个弱信号不能直接支持 confirmed malicious。
- 必须检查适用的合法来源、批准基线和业务解释。
- Coverage 不完整时必须降低结论或记录限制。
- Verdict 引用必须解析到已验证 Fact/Finding，攻击路径边必须引用 Evidence。

## 模型职责

LLM 可以提出候选结论和解释，但最低证据门槛、引用完整性和禁止组合由版本化策略校验。策略阈值需要真实案件集校准，并保留版本。

各场景的具体门槛见 [scenarios](scenarios/common.md)。
