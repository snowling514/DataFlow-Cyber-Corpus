# DataFlow 网络安全语料构建实验

本仓库用于保存基于 DataFlow 的网络安全语料构建实验代码与样例数据。项目目标是从公开安全数据源中整理原始漏洞/安全数据，经过清洗、过滤、去重和格式转换，生成更接近大语言模型训练所需的 QA 与 SFT 格式语料。

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

其中 `pandas`、`requests`、`simhash` 会随 `open-dataflow` 及脚本依赖一起安装或被环境使用。

建议使用虚拟环境：

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install open-dataflow
```

如果运行公开数据源抓取脚本，需要能访问 CISA、NVD、FIRST EPSS、GitHub、UNB、UNSW 等公开网站。

## 2. 仓库内容

- `scripts/`：可复现实验脚本，包括基础案例实验、公开数据源抓取、语料 V1 构建、新内容处理等。
- `source_sample_corpus/`：从公开网络安全数据源汇总得到的样例来源语料。
- `cyber_training_corpus_v1/`：转换后的 V1 训练语料，包括原始来源记录、QA 问答语料和 SFT 指令语料。
- `experiments/`：DataFlow 基础案例实验的输入与输出文件。
- `results/`：用户输入新内容后的处理结果输出目录。仓库仅保留目录占位文件，实际运行产物不提交。

说明：`*.txt` 报告文件和 `results/` 下的运行产物已通过 `.gitignore` 排除，不会提交到仓库。

## 3. 数据来源

样例语料主要来自以下公开来源：

- CISA Known Exploited Vulnerabilities Catalog
- NVD CVE API
- FIRST EPSS API
- CVEProject cvelistV5
- CICIDS2017 数据集说明
- UNSW-NB15 数据集说明

其中，NVD、CISA KEV、EPSS 和 cvelistV5 主要用于构建漏洞知识来源；CICIDS2017 和 UNSW-NB15 作为入侵检测/流量数据集说明型语料加入。

## 4. 语料格式

本项目生成三类主要训练语料：

- `cyber_corpus_v1_raw_sources.jsonl`：保留公开来源字段和原始摘要，便于追溯。
- `cyber_corpus_v1_qa.jsonl`：问答格式样本，适合问答训练或检索问答评估。
- `cyber_corpus_v1_sft.jsonl`：指令微调格式样本，包含 `instruction`、`input`、`output` 字段。

当前 V1 样本规模较小，主要用于验证 DataFlow 流水线和语料构建流程，不适合作为完整模型训练数据集。

## 5. DeepSeek 在线模式

涉及 DeepSeek 的案例默认采用在线模式，需要在本地环境变量中配置 API Key。API Key 不应写入代码，也不应提交到 GitHub。

```powershell
$env:DF_API_KEY = "your_deepseek_api_key"
```

如果你的网络需要代理，可以在本地自行设置，例如：

```powershell
$env:HTTPS_PROXY = "http://your-proxy-host:port"
$env:HTTP_PROXY = "http://your-proxy-host:port"
$env:ALL_PROXY = "http://your-proxy-host:port"
```

不需要代理的环境不用设置这些变量。

## 6. 脚本启动方式

### 6.1 抓取公开来源样例语料

```powershell
python scripts/fetch_source_sample_corpus.py
```

输入：无手动输入，脚本会访问公开数据源。

输出：

- `source_sample_corpus/sample_cyber_corpus_from_sources.jsonl`
- `source_sample_corpus/fetch_metadata.json`

预期结果：生成包含漏洞记录和数据集说明记录的样例来源语料。

### 6.2 构建 V1 QA/SFT 训练语料

```powershell
python scripts/build_training_corpus_v1.py
```

输入：

- `source_sample_corpus/sample_cyber_corpus_from_sources.jsonl`

输出：

- `cyber_training_corpus_v1/cyber_corpus_v1_raw_sources.jsonl`
- `cyber_training_corpus_v1/cyber_corpus_v1_qa.jsonl`
- `cyber_training_corpus_v1/cyber_corpus_v1_sft.jsonl`
- `cyber_training_corpus_v1/build_metadata.json`

预期结果：生成原始来源、QA 问答和 SFT 指令三类 V1 语料。

### 6.3 运行 9 个 DataFlow 案例实验

```powershell
.\scripts\run_dataflow_cases.ps1
```

输入：脚本内置小型案例数据；第 8、9 个案例需要本地设置 `DF_API_KEY`。

输出：

- `experiments/` 下各案例输入和输出文件

预期结果：依次展示清洗、过滤、去重、DeepSeek 生成等 DataFlow 案例。

### 6.4 输入新内容并导出处理结果

脚本：

```powershell
python scripts/process_new_content.py
```

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

预期结果：输入新的网络安全文本后，脚本会导出清洗后的记录，并自动生成基础 QA 与 SFT 样本，便于后续人工检查或追加到语料库。

## 7. 新内容处理流程

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
  -> 导出 processed / QA / SFT / summary
```

## 8. 实验流程

整体流程如下：

```text
公开安全数据源
  -> 来源样例语料汇总
  -> DataFlow 清洗与过滤
  -> 字段标准化与去重
  -> QA / SFT 格式转换
  -> V1 语料与初步质量评估
```

## 9. 预期结果

完成环境配置并运行脚本后，预期可以得到：

1. 可追溯的公开安全来源样例语料。
2. QA 问答格式训练样本。
3. SFT 指令微调格式训练样本。
4. 针对用户新输入文本的处理结果。
5. 可复现的 DataFlow 清洗、过滤、去重流程。

## 10. 后续方向

- 扩大 CVE 样本数量，覆盖更多 CWE、严重等级和厂商产品。
- 引入人工抽检，评估事实一致性、答案完整性和幻觉风险。
- 使用 DeepSeek 等模型进行问题多样化生成，但答案事实仍由结构化字段约束。
- 增加日志解释、IOC 提取、风险排序和处置步骤生成等任务类型。
- 拆分 train/dev/test，为后续小模型微调实验做准备。
