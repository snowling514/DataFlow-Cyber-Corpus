# DataFlow 网络安全语料构建实验

本仓库用于保存基于 DataFlow 的网络安全语料构建实验代码与样例数据。项目目标是从公开安全数据源中整理原始漏洞/安全数据，经过清洗、过滤、去重和格式转换，生成更接近大语言模型训练所需的 QA 与 SFT 格式语料。

## 仓库内容

- `scripts/`：可复现实验脚本，包括基础案例实验、公开数据源抓取、语料 V1 构建等。
- `source_sample_corpus/`：从公开网络安全数据源汇总得到的样例来源语料。
- `cyber_training_corpus_v1/`：转换后的 V1 训练语料，包括原始来源记录、QA 问答语料和 SFT 指令语料。
- `experiments/`：DataFlow 基础案例实验的输入与输出文件。

说明：`*.txt` 报告文件已通过 `.gitignore` 排除，不会提交到仓库。

## 数据来源

样例语料主要来自以下公开来源：

- CISA Known Exploited Vulnerabilities Catalog
- NVD CVE API
- FIRST EPSS API
- CVEProject cvelistV5
- CICIDS2017 数据集说明
- UNSW-NB15 数据集说明

其中，NVD、CISA KEV、EPSS 和 cvelistV5 主要用于构建漏洞知识来源；CICIDS2017 和 UNSW-NB15 作为入侵检测/流量数据集说明型语料加入。

## 语料格式

本项目生成三类主要文件：

- `cyber_corpus_v1_raw_sources.jsonl`：保留公开来源字段和原始摘要，便于追溯。
- `cyber_corpus_v1_qa.jsonl`：问答格式样本，适合问答训练或检索问答评估。
- `cyber_corpus_v1_sft.jsonl`：指令微调格式样本，包含 `instruction`、`input`、`output` 字段。

当前 V1 样本规模较小，主要用于验证 DataFlow 流水线和语料构建流程，不适合作为完整模型训练数据集。

## 环境准备

建议使用 Python 虚拟环境：

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install open-dataflow
```

## DeepSeek 在线模式

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

## 运行脚本

如果需要重新抓取公开来源样例语料：

```powershell
python scripts/fetch_source_sample_corpus.py
```

如果需要重新生成 V1 QA/SFT 训练语料：

```powershell
python scripts/build_training_corpus_v1.py
```

如果需要运行 9 个 DataFlow 案例实验：

```powershell
.\scripts\run_dataflow_cases.ps1
```

## 实验流程

整体流程如下：

```text
公开安全数据源
  -> 来源样例语料汇总
  -> DataFlow 清洗与过滤
  -> 字段标准化与去重
  -> QA / SFT 格式转换
  -> V1 语料与初步质量评估
```

## 后续方向

- 扩大 CVE 样本数量，覆盖更多 CWE、严重等级和厂商产品。
- 引入人工抽检，评估事实一致性、答案完整性和幻觉风险。
- 使用 DeepSeek 等模型进行问题多样化生成，但答案事实仍由结构化字段约束。
- 增加日志解释、IOC 提取、风险排序和处置步骤生成等任务类型。
- 拆分 train/dev/test，为后续小模型微调实验做准备。

