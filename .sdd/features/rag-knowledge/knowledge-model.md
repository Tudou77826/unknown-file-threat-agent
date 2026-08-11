# Knowledge Model

每个 `KnowledgeItem` 至少包含：

```text
knowledge_id
tenant_id
knowledge_domain
document_type
title
source_uri
owner
version
effective_from
expires_at
confidentiality
acl
applicable_scenarios
applicable_asset_types
content_hash
chunk_id
```

## 历史案件

历史案件进入检索前必须标明案件质量、最终状态、租户、脱敏级别、Verdict 版本和是否允许跨案件使用。相似性结果只产生候选解释，不复制历史结论。

## 引用

`KnowledgeRef` 必须定位到 `knowledge_id + version + chunk_id`。文档更新后旧引用仍需可追溯，或明确返回已撤回状态。
