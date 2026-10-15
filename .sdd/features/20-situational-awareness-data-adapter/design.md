# 态势感知数据适配模块 — 接口设计

## 1. 模块职责

研判系统通过统一接口查询态势感知数据，适配模块负责读取源数据、字段转换及必要的关联与合并。数据库查询、IR 调用及二者的组合是模块内部实现，切换时不改变上层接口。

调用关系：`研判工具 → 数据查询接口 → 态势感知 Adapter → 数据库 / IR`。

模块与态势感知系统在内网一起维护。本 Feature 只定义模块接口和数据约定，具体部署与通信方式在接入时确定。

## 2. 接口

### 已有接口直接复用

沿用 `data_foundation/ports/investigation_data.py` 中的 `InvestigationDataPort`，由态势感知 Adapter 实现，不再定义一套重复接口。

| 接口 | 输入 | 输出 |
|---|---|---|
| `query_process` | `ProcessActivityQuery` | `ActivityQueryResult` |
| `query_file` | `FileActivityQuery` | `ActivityQueryResult` |
| `query_network` | `NetworkActivityQuery` | `ActivityQueryResult` |
| `resolve_entity` | 租户、实体引用 | `EntityIdentity` 或未找到 |
| `find_relations` | 租户、实体引用、方向 | `ObservedRelation` 列表 |
| `list_entity_timeline` | `EntityTimelineQuery` | `EntityTimelinePage` |
| `get_activities` | 租户、活动引用列表 | 对应活动列表 |
| `get_raw_record` | 租户、活动引用 | `ActivityRawRecord` 或未找到 |

已有 Socket、服务、软件包和扩展查询接口继续保留；源端没有对应能力时明确返回不支持。

认证查询补入聚合接口：`query_authentication(AuthenticationActivityQuery) -> ActivityQueryResult`。认证活动模型、查询参数和底层查询已有定义，需补齐聚合 Port 与 Adapter 的转发方法。

### 按本次接入补充的接口

以下为待新增的方法和数据类型，归入同一数据访问边界。

| 接口 | 输入 | 输出 |
|---|---|---|
| `query_alerts` | `AlertQuery`：查询范围、时间、分页 | `QueryPage[UnknownFileAlert]` |
| `query_file_reputation` | 查询范围、`FileHash`：算法与摘要 | `FileReputation` |
| `get_asset_info` | 查询范围、主机引用 | `AssetInfo` 或未找到 |
| `query_source_assessments` | `AssessmentQuery`：查询范围、实体、时间、分页 | `QueryPage[SourceAssessment]` |

## 3. 输入输出约定

活动查询沿用现有强类型参数和 `ActivityQueryResult`，包括接口字段说明、实际查询范围、活动、来源及分页信息。新增查询也复用现有 `Scope`，上层不传 SQL、源表名或 IR 参数。

| 新增类型 | 最小内容 |
|---|---|
| `QueryPage[T]` | 记录列表、下一页游标；有下一页表示尚未取完 |
| `UnknownFileAlert` | 源告警 ID、主机、检测时间、文件路径及哈希、进程和容器线索、原文引用 |
| `FileReputation` | 文件哈希、各类基线/黑白名单命中、查询的名单范围、查询时间及源端备注；允许多项命中 |
| `AssetInfo` | 主机标识、资产属性、来源及更新时间 |
| `SourceAssessment` | 源记录 ID、关联实体、结论或信誉分、产生方式（人工/规则/模型/未知）、时间及依据引用 |

各结果保留源系统与原记录标识；字段缺失保持空值。文件事件中的操作进程哈希和目标文件哈希分别映射，不能混用；进程关联有歧义时沿用候选关系表达。

成功查询无匹配记录，返回空列表或未找到；源端不支持和查询失败，通过明确的异常原因区分，不能伪装为空结果。组合查询只完成一部分时返回明确失败原因，首版不新增部分成功协议。

文件信誉只表达源端收录或判断，资产信息只表达属性，源端研判只表达外部结论；适配模块不据此生成攻击活动或最终 Verdict。

## 4. 实现与验证

在 `data_foundation/adapters` 实现 `SituationalAwarenessDataAdapter`，在 `bootstrap` 注入现有数据 Port。Adapter 内部按能力选择数据库或 IR，字段转换和必要关联均在模块内完成。

先用源端样本验证查询、字段转换和错误语义，再接一个真实告警验证研判工具能取得数据。替换数据库或 IR 实现后，同一输入应保持相同的输出含义，上层调查逻辑无需修改。
