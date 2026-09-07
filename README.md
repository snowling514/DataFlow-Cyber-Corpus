# DataFlow 网络安全语料构建实验

本仓库用于保存基于 DataFlow 的网络安全语料构建实验代码与样例数据。项目目标是从公开安全数据源中整理原始漏洞/安全数据，经过清洗、过滤、去重和格式转换，生成更接近大语言模型训练所需的 QA 与 SFT 指令格式语料。

## 1. 环境依赖

推荐环境：

- Windows 10/11 或其他支持 Python 的系统
- Python 3.10 及以上
- Git
- 可选：PowerShell，用于运行 `.ps1` 示例脚本

核心 Python 依赖：

- `open-dataflow`
- `pandas`
- `requests`
- `simhash`

建议使用虚拟环境：

```powershell
python -m venv .venv
.\.venv\Scripts\activate
python -m pip install -r requirements.txt
```

安装完成后建议先运行环境检查：

```powershell
python scripts/check_environment.py
```

如果系统默认 `python` 指向了其他解释器，建议显式使用虚拟环境中的 Python：

```powershell
.\.venv\Scripts\python.exe scripts/check_environment.py
```

如果运行公开数据源抓取脚本，需要能访问 CISA、NVD、FIRST EPSS、GitHub、UNB、UNSW 等公开网站。

## 2. 仓库内容

- `scripts/`：可复现实验脚本，包括基础案例实验、环境检查、公开数据源抓取、语料 V1 构建、新内容处理、质量评估、manifest 生成和项目级验收等。
- `requirements.txt`：项目核心 Python 依赖清单。
- `config/`：流水线配置文件，集中管理语料文件名、schema 路径、清洗阈值、质量门禁和领域关键词。
- `schemas/`：语料字段规范，分别约束来源记录、QA 样本和 SFT 指令格式样本。
- `source_sample_corpus/`：从公开网络安全数据源汇总得到的样例来源语料。
- `cyber_training_corpus_v1/`：转换后的 V1 训练语料，包括原始来源记录、QA 问答语料和 SFT 指令语料。
- `experiments/`：DataFlow 基础案例实验的输入与输出文件。
- `results/`：用户输入新内容后的处理结果输出目录。仓库仅保留目录占位文件，实际运行产物不提交。
- `DATA_CARD.md`：V1 语料的数据说明卡，说明来源、文件组成、质量检查、适用场景和限制。

## 3. 数据来源

样例语料主要来自以下公开来源：

- CISA Known Exploited Vulnerabilities Catalog
- NVD CVE API
- FIRST EPSS API
- CVEProject cvelistV5
- CICIDS2017 数据集说明
- UNSW-NB15 数据集说明

其中，NVD、CISA KEV、EPSS 和 cvelistV5 主要用于构建漏洞知识来源；CICIDS2017 和 UNSW-NB15 作为入侵检测/流量数据集说明型语料加入。

更完整的数据说明见 `DATA_CARD.md`。

## 4. 语料格式

本项目生成三类主要训练语料，并在 `schemas/` 下提供对应字段规范：

- `cyber_corpus_v1_raw_sources.jsonl`：保留公开来源字段和原始摘要，便于追溯；对应 `schemas/cyber_raw_source.schema.json`。
- `cyber_corpus_v1_qa.jsonl`：问答格式样本，适合问答训练或检索问答评估；对应 `schemas/cyber_qa.schema.json`。
- `cyber_corpus_v1_sft.jsonl`：SFT 指令格式样本，包含 `instruction`、`input`、`output` 字段；对应 `schemas/cyber_sft.schema.json`。

当前 V1 样本规模较小，主要用于验证 DataFlow 流水线和语料构建流程，不适合作为完整模型训练数据集。

## 5. 流水线配置

默认配置文件为 `config/pipeline_config.json`，其中包含：

- `corpus.files`：V1 语料输入输出文件名，包括质量指标和语料 manifest 文件名。
- `schemas.files`：raw、QA、SFT 三类语料对应的 schema 文件。
- `processing_defaults`：新内容处理脚本默认使用的词数、唯一词比例和 SimHash 去重阈值。
- `quality_gate`：质量评估脚本使用的 schema、字段完整性、来源追溯和领域覆盖率门禁。
- `cyber_terms`：网络安全领域关键词，用于新内容标注和语料质量覆盖率统计。

`build_training_corpus_v1.py`、`process_new_content.py` 和 `evaluate_training_corpus.py` 均支持通过 `--config` 指定其他配置文件，便于对比不同输出目录、清洗阈值或质量门禁。

## 6. DeepSeek 在线模式

涉及 DeepSeek 的案例默认采用在线模式，需要在本地环境变量中配置 API Key。

当前项目中，凡是 QA/SFT 数据合成、问题多样化生成、答案表达优化等适合由大模型完成的环节，均使用 DeepSeek 在线调用完成。脚本会把公开来源字段或用户输入文本作为约束上下文传给 DeepSeek，并要求模型只依据输入内容生成训练样本；缺失信息应输出“来源未提供”或“文本未提供”，避免补写来源中不存在的事实。

```powershell
$env:DF_API_KEY = "your_deepseek_api_key"
```

## 7. 脚本启动方式

### 7.1 抓取公开来源样例语料

```powershell
python scripts/fetch_source_sample_corpus.py
```

输入：无手动输入，脚本会访问公开数据源。

输出：

- `source_sample_corpus/sample_cyber_corpus_from_sources.jsonl`
- `source_sample_corpus/fetch_metadata.json`

预期结果：生成包含漏洞记录和数据集说明记录的样例来源语料。

### 7.2 构建 V1 QA/SFT 指令格式语料

```powershell
python scripts/build_training_corpus_v1.py
```

可选：使用 `--config config/pipeline_config.json` 指定语料文件名和输出目录配置。

运行前需要设置 `DF_API_KEY`，该脚本会调用 DeepSeek 生成 QA 与 SFT 训练样本。

输入：

- `source_sample_corpus/sample_cyber_corpus_from_sources.jsonl`

输出：

- `cyber_training_corpus_v1/cyber_corpus_v1_raw_sources.jsonl`
- `cyber_training_corpus_v1/cyber_corpus_v1_qa.jsonl`
- `cyber_training_corpus_v1/cyber_corpus_v1_sft.jsonl`
- `cyber_training_corpus_v1/build_metadata.json`

预期结果：生成原始来源、QA 问答和 SFT 指令三类 V1 语料；元数据中会记录 `generation_mode=deepseek-chat`。

### 7.3 运行 9 个 DataFlow 案例实验

```powershell
.\scripts\run_dataflow_cases.ps1
```

输入：脚本内置小型案例数据；第 8、9 个案例需要本地设置 `DF_API_KEY`。

输出：

- `experiments/` 下各案例输入和输出文件

预期结果：依次展示清洗、过滤、去重、DeepSeek 生成等 DataFlow 案例。

### 7.4 输入新内容并导出处理结果

脚本：

```powershell
python scripts/process_new_content.py
```

可选：使用 `--config config/pipeline_config.json` 指定流水线配置。

运行前需要设置 `DF_API_KEY`。该脚本先使用 DataFlow 对新文本进行清洗、过滤和去重，再调用 DeepSeek 基于处理后的文本生成 QA 与 SFT 样本。

支持三种输入方式。

方式一：直接传入一段文本：

```powershell
python scripts/process_new_content.py --text "CVE-2025-0001 allows remote attackers to exploit an authentication bypass on the VPN gateway." --title "VPN authentication bypass sample"
```

方式二：读取文件：

```powershell
python scripts/process_new_content.py --input-file .\my_input.txt
python scripts/process_new_content.py --input-file .\my_input.jsonl
```

方式三：交互输入：

```powershell
python scripts/process_new_content.py
```

交互模式下，输入多行文本后，单独输入一行 `END` 结束。

支持的输入文件格式：

- `.txt`：按空行分段，每段作为一条记录。
- `.json`：支持单个对象或对象数组。
- `.jsonl`：每行一个 JSON 对象。

推荐输入字段：

```json
{"id":"sample_001","title":"样例标题","text":"需要处理的网络安全文本","source_type":"manual"}
```

如果输入 JSON 中没有 `text` 字段，脚本会尝试读取 `description`、`content` 或 `raw_content` 字段。

输出目录：

```text
results/<运行时间>/
```

每次运行会生成：

- `input.jsonl`：规范化后的输入。
- `processed.jsonl`：DataFlow 清洗、过滤、去重后的文本。
- `qa.jsonl`：基于处理后文本生成的问答样本。
- `sft.jsonl`：基于处理后文本生成的 SFT 指令样本。
- `summary.json`：本次运行的统计摘要。

同时会在 `results/` 下更新：

- `latest_processed.jsonl`
- `latest_qa.jsonl`
- `latest_sft.jsonl`
- `latest_summary.json`

预期结果：输入新的网络安全文本后，脚本会导出清洗后的记录，并通过 DeepSeek 自动生成 QA 与 SFT 样本，便于后续人工检查或追加到语料库。


### 7.5 评估 V1 QA/SFT 语料质量

```powershell
python scripts/evaluate_training_corpus.py
```

可选：使用 `--config config/pipeline_config.json` 指定质量门禁配置。

输入：

- `cyber_training_corpus_v1/cyber_corpus_v1_raw_sources.jsonl`
- `cyber_training_corpus_v1/cyber_corpus_v1_qa.jsonl`
- `cyber_training_corpus_v1/cyber_corpus_v1_sft.jsonl`

输出：

- `cyber_training_corpus_v1/quality_metrics.json`

预期结果：生成字段完整性、schema 类型校验、唯一 ID、任务类型分布、来源追溯、领域术语覆盖和记录链接关系等质量指标，用于复核语料流水线效果。


### 7.6 生成语料 manifest

```powershell
python scripts/generate_corpus_manifest.py
```

输入：无需额外输入，脚本会读取默认配置、schema、V1 语料文件、关键脚本和说明文件。

输出：

- `cyber_training_corpus_v1/corpus_manifest.json`

预期结果：生成包含文件路径、用途、大小、行数和 SHA256 哈希的语料交付清单，便于后续复核 V1 语料对应的配置和脚本版本。

### 7.7 运行项目级验收检查

```powershell
python scripts/run_project_checks.py
```

输入：无需额外输入，脚本会读取默认配置、schema、manifest 和 V1 语料文件。

输出：终端输出依赖、JSON、schema、Python 编译、语料质量门禁、manifest 一致性、敏感信息扫描和项目口径扫描结果。

预期结果：所有本地可复现检查通过，并显示 `All project checks passed.`。该脚本不调用 DeepSeek，不需要设置 `DF_API_KEY`。

## 8. 新内容处理流程

`process_new_content.py` 的内部流程如下：

```text
用户输入文本/文件
  -> 规范化为 JSONL
  -> HtmlUrlRemoverRefiner
  -> RemoveExtraSpacesRefiner
  -> ContentNullFilter
  -> WordNumberFilter
  -> UniqueWordsFilter
  -> SimHashDeduplicateFilter
  -> 关键词命中统计
  -> DeepSeek 生成 QA/SFT 样本
  -> 导出 processed / QA / SFT / summary
```

## 9. 实验流程

整体流程如下：

```text
公开安全数据源
  -> 来源样例语料汇总
  -> DataFlow 清洗与过滤
  -> 字段标准化与去重
  -> DeepSeek QA / SFT 格式生成
  -> V1 语料与初步质量评估
  -> 流水线指标复核与迭代优化
```

## 10. 预期结果

完成环境配置并运行脚本后，预期可以得到：

1. 可追溯的公开安全来源样例语料。
2. QA 问答格式训练样本。
3. SFT 指令格式训练样本。
4. 针对用户新输入文本的处理结果。
5. 可复现的 DataFlow 清洗、过滤、去重、质量评估、语料 manifest 和项目验收流程。

## 11. 后续方向

- 扩大 CVE 样本数量，覆盖更多 CWE、严重等级和厂商产品。
- 引入人工抽检，评估事实一致性、答案完整性和幻觉风险。
- 持续使用 DeepSeek 进行问题多样化、SFT 合成和答案表达优化，但答案事实仍由结构化字段或输入文本约束。
- 增加日志解释、IOC 提取、风险排序和处置步骤生成等任务类型。
- 设计数据版本划分、抽检集合和质量复核流程，为后续语料迭代做准备。

