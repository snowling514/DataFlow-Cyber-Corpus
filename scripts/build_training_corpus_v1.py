from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from deepseek_utils import deepseek_json, require_api_key, validate_list_payload

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "source_sample_corpus" / "sample_cyber_corpus_from_sources.jsonl"
OUT = ROOT / "cyber_training_corpus_v1"
OUT.mkdir(parents=True, exist_ok=True)
RAW_OUT = OUT / "cyber_corpus_v1_raw_sources.jsonl"
QA_OUT = OUT / "cyber_corpus_v1_qa.jsonl"
SFT_OUT = OUT / "cyber_corpus_v1_sft.jsonl"
REPORT_OUT = OUT / "initial_quality_report.txt"
METADATA_OUT = OUT / "build_metadata.json"


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def clean_text(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def cve_context(row: dict[str, Any]) -> str:
    cisa = row.get("cisa", {})
    nvd = row.get("nvd", {})
    epss = row.get("epss", {})
    cvelist = row.get("cvelist_v5", {})
    parts = [
        f"CVE ID: {row.get('cve_id', '')}",
        f"Vendor/Product: {clean_text(cisa.get('vendorProject'))} / {clean_text(cisa.get('product'))}",
        f"Vulnerability name: {clean_text(row.get('title'))}",
        f"CISA short description: {clean_text(cisa.get('shortDescription'))}",
        f"NVD description: {clean_text(nvd.get('nvd_description'))}",
        f"CNA description: {clean_text(cvelist.get('cna_description'))}",
        f"CVSS severity/base score: {clean_text(nvd.get('cvss_severity'))} / {clean_text(nvd.get('cvss_base_score'))}",
        f"CWE: {', '.join(nvd.get('cwe') or cisa.get('cwes') or [])}",
        f"CISA date added/due date: {clean_text(cisa.get('dateAdded'))} / {clean_text(cisa.get('dueDate'))}",
        f"Known ransomware campaign use: {clean_text(cisa.get('knownRansomwareCampaignUse'))}",
        f"Required action: {clean_text(cisa.get('requiredAction'))}",
        f"EPSS score/percentile/date: {clean_text(epss.get('epss'))} / {clean_text(epss.get('percentile'))} / {clean_text(epss.get('date'))}",
    ]
    return "\n".join(p for p in parts if not p.endswith(": ") and not p.endswith("/ "))



def qa(record_id: str, qtype: str, question: str, answer: str, source: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"qa_{record_id}_{qtype}",
        "record_id": record_id,
        "task_type": qtype,
        "question": clean_text(question),
        "answer": clean_text(answer),
        "source_refs": source,
        "corpus_version": "V1",
    }


def sft(record_id: str, stype: str, instruction: str, input_text: str, output: str, source: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"sft_{record_id}_{stype}",
        "record_id": record_id,
        "task_type": stype,
        "instruction": clean_text(instruction),
        "input": clean_text(input_text),
        "output": clean_text(output),
        "source_refs": source,
        "corpus_version": "V1",
    }


def source_refs(row: dict[str, Any]) -> dict[str, Any]:
    refs = row.get("source_urls", {}).copy()
    if row.get("cve_id"):
        refs["cve_id"] = row.get("cve_id")
    return refs



def build_with_deepseek(row: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    require_api_key()
    rid = row["record_id"]
    refs = source_refs(row)
    if row.get("record_type") == "vulnerability_text":
        context = cve_context(row)
        qa_count = 5
        sft_count = 3
        focus = "漏洞解释、影响产品、风险评估、修复建议、CWE/弱点抽取"
    else:
        context = clean_text(row.get("text"))
        qa_count = 2
        sft_count = 1
        focus = "数据集用途说明、为什么不能直接作为问答训练语料、如何转成训练任务"

    system_prompt = (
        "你是网络安全大模型训练语料构建专家。"
        "你必须严格依据输入来源字段生成 QA 和 SFT 数据，不得编造没有出现在输入中的 CVE、厂商、产品、分数、CWE 或日期。"
        "如果信息缺失，写'来源未提供'。输出必须是严格 JSON，不要 Markdown。"
    )
    user_payload = {
        "task": "合成网络安全训练语料 V1",
        "requirements": [
            f"生成 {qa_count} 条中文 QA，覆盖：{focus}。",
            f"生成 {sft_count} 条中文 SFT，每条包含 instruction、input、output。",
            "QA 每条包含 task_type、question、answer。",
            "SFT 每条包含 task_type、instruction、input、output。",
            "语言要适合大模型训练，答案清晰、可追溯、不要添加来源中没有的事实。",
        ],
        "output_schema": {
            "qa": [{"task_type": "string", "question": "string", "answer": "string"}],
            "sft": [{"task_type": "string", "instruction": "string", "input": "string", "output": "string"}],
        },
        "source_record": row,
        "normalized_context": context,
    }
    payload = deepseek_json(system_prompt, json.dumps(user_payload, ensure_ascii=False), temperature=0.2)
    qa_rows = []
    sft_rows = []
    for idx, item in enumerate(validate_list_payload(payload, "qa"), 1):
        qa_rows.append(qa(
            rid,
            clean_text(item.get("task_type") or f"deepseek_qa_{idx:02d}"),
            clean_text(item.get("question")),
            clean_text(item.get("answer")),
            refs,
        ) | {"generation_model": "deepseek-chat"})
    for idx, item in enumerate(validate_list_payload(payload, "sft"), 1):
        sft_rows.append(sft(
            rid,
            clean_text(item.get("task_type") or f"deepseek_sft_{idx:02d}"),
            clean_text(item.get("instruction")),
            clean_text(item.get("input") or context),
            clean_text(item.get("output")),
            refs,
        ) | {"generation_model": "deepseek-chat"})
    return qa_rows, sft_rows

def quality(rows: list[dict[str, Any]], fields: list[str]) -> dict[str, Any]:
    ids = [r["id"] for r in rows]
    lengths = []
    missing = Counter()
    for r in rows:
        joined = " ".join(clean_text(r.get(f, "")) for f in fields)
        lengths.append(len(joined))
        for f in fields:
            if not clean_text(r.get(f, "")):
                missing[f] += 1
    return {
        "count": len(rows),
        "unique_id_count": len(set(ids)),
        "duplicate_id_count": len(ids) - len(set(ids)),
        "min_chars": min(lengths) if lengths else 0,
        "max_chars": max(lengths) if lengths else 0,
        "avg_chars": round(sum(lengths) / len(lengths), 2) if lengths else 0,
        "missing_fields": dict(missing),
        "task_type_counts": dict(Counter(r.get("task_type", "unknown") for r in rows)),
    }


def main() -> None:
    source_rows = load_jsonl(SOURCE)
    raw_rows = []
    qa_rows = []
    sft_rows = []
    for row in source_rows:
        raw = {
            "record_id": row["record_id"],
            "record_type": row["record_type"],
            "title": row.get("title"),
            "text": clean_text(row.get("text")),
            "primary_source": row.get("primary_source"),
            "source_urls": row.get("source_urls", {}),
            "cve_id": row.get("cve_id"),
            "tags": row.get("tags", []),
            "corpus_version": "V1_raw_sources",
        }
        raw_rows.append(raw)
        qas, sfts = build_with_deepseek(row)
        qa_rows.extend(qas)
        sft_rows.extend(sfts)

    write_jsonl(RAW_OUT, raw_rows)
    write_jsonl(QA_OUT, qa_rows)
    write_jsonl(SFT_OUT, sft_rows)

    qa_q = quality(qa_rows, ["question", "answer"])
    sft_q = quality(sft_rows, ["instruction", "input", "output"])
    raw_q = quality([{"id": r["record_id"], **r} for r in raw_rows], ["title", "text"])
    metadata = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source_file": str(SOURCE),
        "generation_mode": "deepseek-chat",
        "outputs": {
            "raw_sources": str(RAW_OUT),
            "qa": str(QA_OUT),
            "sft": str(SFT_OUT),
            "report": str(REPORT_OUT),
        },
        "counts": {
            "source_records": len(source_rows),
            "raw_records": len(raw_rows),
            "qa_records": len(qa_rows),
            "sft_records": len(sft_rows),
        },
        "quality": {"raw": raw_q, "qa": qa_q, "sft": sft_q},
    }
    METADATA_OUT.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        "网络安全训练语料 V1 初步质量报告",
        "================================",
        "",
        f"生成时间：{metadata['generated_at']}",
        f"来源文件：{SOURCE}",
        "",
        "一、产出文件",
        "------------",
        f"1. 原始来源语料：{RAW_OUT}",
        f"2. 问答语料：{QA_OUT}",
        f"3. SFT 指令语料：{SFT_OUT}",
        f"4. 构建元数据：{METADATA_OUT}",
        "",
        "二、样本数量",
        "------------",
        f"来源记录数：{len(source_rows)}",
        f"原始来源记录数：{len(raw_rows)}",
        f"问答样本数：{len(qa_rows)}",
        f"SFT 样本数：{len(sft_rows)}",
        "",
        "三、质量检查",
        "------------",
        f"QA 唯一 ID 数：{qa_q['unique_id_count']}，重复 ID 数：{qa_q['duplicate_id_count']}",
        f"QA 平均字符数：{qa_q['avg_chars']}，最短：{qa_q['min_chars']}，最长：{qa_q['max_chars']}",
        f"QA 任务类型分布：{qa_q['task_type_counts']}",
        f"SFT 唯一 ID 数：{sft_q['unique_id_count']}，重复 ID 数：{sft_q['duplicate_id_count']}",
        f"SFT 平均字符数：{sft_q['avg_chars']}，最短：{sft_q['min_chars']}，最长：{sft_q['max_chars']}",
        f"SFT 任务类型分布：{sft_q['task_type_counts']}",
        "",
        "四、构建策略说明",
        "----------------",
        "本版 V1 训练语料使用 DeepSeek 在线合成 QA 与 SFT 样本，但生成过程受到 CISA KEV、NVD、FIRST EPSS 和 CVEProject cvelistV5 的结构化字段约束。脚本要求模型缺失信息写'来源未提供'，以降低幻觉风险，并保证问题、答案、指令输出都能追溯到原始来源。",
        "",
        "五、适用性说明",
        "--------------",
        "这些样本已经比原始数据库记录更接近大模型训练格式：QA 文件适合问答训练或检索问答评估，SFT 文件适合指令微调格式。但由于样本量仍较小，它目前是 V1 样例语料，不适合直接训练完整模型，只适合验证流水线、报告展示和小规模微调冒烟测试。",
        "",
        "六、后续优化方向",
        "----------------",
        "1. 扩大 CVE 数量，例如每类 CWE 或每种严重等级采样 50-100 条。",
        "2. 继续使用 DeepSeek 做语言润色、多样化提问和 SFT 合成，但答案事实仍必须由结构化字段约束。",
        "3. 增加人工抽检字段：事实正确性、答案完整性、是否包含幻觉、是否泄露无关信息。",
        "4. 拆分 train/dev/test，并记录随机种子和数据版本。",
        "5. 加入更多任务类型，例如漏洞分类、风险排序、处置步骤生成、日志解释和 IOC 提取。",
        "",
    ]
    REPORT_OUT.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps(metadata, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

