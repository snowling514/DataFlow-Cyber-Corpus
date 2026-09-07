# 网络安全语料数据说明卡

## 1. 数据集名称

DataFlow 网络安全语料 V1。

## 2. 建设目标

本语料用于验证网络安全领域数据从公开来源到大语言模型训练样本的处理流程，重点关注数据抓取、字段标准化、清洗过滤、去重、QA/SFT 格式转换、质量评估和可复现交付。

当前 V1 版本规模较小，定位为流程验证与样例语料，不作为完整生产级训练数据集。

## 3. 数据来源

样例语料来自公开网络安全数据源和公开数据集说明，主要包括：

- CISA Known Exploited Vulnerabilities Catalog
- NVD CVE API
- FIRST EPSS API
- CVEProject cvelistV5
- CICIDS2017 数据集说明
- UNSW-NB15 数据集说明

其中，CISA、NVD、EPSS 和 cvelistV5 用于形成漏洞类知识来源；CICIDS2017 和 UNSW-NB15 用于补充入侵检测与网络流量数据集说明类样本。

## 4. 文件组成

核心语料文件位于 `cyber_training_corpus_v1/`：

- `cyber_corpus_v1_raw_sources.jsonl`：标准化后的来源记录，保留公开来源字段与追溯信息。
- `cyber_corpus_v1_qa.jsonl`：QA 问答格式样本。
- `cyber_corpus_v1_sft.jsonl`：SFT 指令格式样本。
- `quality_metrics.json`：语料质量评估结果。
- `corpus_manifest.json`：可复现交付清单，记录关键文件的大小、行数和 SHA256 哈希。
- `build_metadata.json`：语料构建过程元数据。

来源样例文件位于 `source_sample_corpus/`：

- `sample_cyber_corpus_from_sources.jsonl`
- `fetch_metadata.json`

字段约束位于 `schemas/`：

- `cyber_raw_source.schema.json`
- `cyber_qa.schema.json`
- `cyber_sft.schema.json`

## 5. 处理流程

语料处理流程如下：

```text
公开安全数据源
  -> 来源记录汇总
  -> 字段标准化
  -> DataFlow 清洗、过滤、去重
  -> DeepSeek 在线生成 QA/SFT 样本
  -> schema 校验与质量评估
  -> manifest 固化交付状态
```

在 QA/SFT 生成环节，DeepSeek 只基于公开来源字段或用户输入文本生成样本。对于来源中未提供的信息，输出应保留“不提供”“来源未提供”或类似表述，避免补写无法追溯的事实。

## 6. 当前规模

以当前 V1 交付文件为准：

- 来源记录：10 条
- QA 样本：44 条
- SFT 样本：26 条

最新数量应以 `cyber_training_corpus_v1/quality_metrics.json` 和 `cyber_training_corpus_v1/corpus_manifest.json` 为准。

## 7. 质量检查

项目级验收脚本为：

```powershell
python scripts/run_project_checks.py
```

该脚本检查：

- Python 依赖是否安装并可导入
- 配置文件和 schema 是否为合法 JSON
- 核心语料、schema、质量指标和 manifest 是否存在
- Python 脚本是否能通过编译
- QA/SFT 语料是否通过 schema、字段完整性、来源追溯和领域覆盖率门禁
- manifest 是否与当前文件内容一致
- 仓库文本文件中是否误提交 API Key
- 项目说明是否保留了偏离“语料流水线优化”的旧口径

当前 V1 质量门禁结果：

- `hard_failure_count = 0`
- schema 有效率：100%
- 必填字段完整率：100%
- 无重复 ID

## 8. 适用场景

本语料适合用于：

- DataFlow 语料处理流程演示
- 网络安全样例语料格式设计
- QA/SFT 数据合成流程验证
- 语料质量评估指标设计
- 后续扩大数据规模前的流水线原型验证

## 9. 不适用场景

本语料暂不适合直接用于：

- 生产级安全问答系统
- 完整模型训练数据集
- 漏洞处置自动决策
- 漏洞实时监测
- 对外发布为权威漏洞知识库

原因是当前 V1 样本量较小，主要用于流程验证；同时部分生成样本需要继续进行人工抽检和事实一致性复核。

## 10. 风险与限制

- 数据来源虽然公开，但不同来源的字段更新频率和解释口径可能不同。
- 漏洞信息具有时效性，实际风险判断应结合最新公告、补丁状态和资产暴露情况。
- DeepSeek 生成内容需要受来源字段约束，并通过人工抽检降低幻觉风险。
- 清洗规则不能简单删除端口号、版本号、CVE 编号、URL、路径和符号，因为这些内容在网络安全语境中可能是关键信息。

## 11. 后续改进方向

- 扩大 CVE、CWE、厂商产品和攻击类型覆盖范围。
- 增加人工抽检记录，形成事实一致性复核样本。
- 细化任务类型，如漏洞解释、风险分级、处置建议、IOC 提取、日志解释和字段抽取。
- 优化去重和质量门禁阈值，减少模板化表达。
- 建立 V2 版本的数据变更记录和评估对比表。
