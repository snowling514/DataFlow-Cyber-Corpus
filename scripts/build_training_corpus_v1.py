from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

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


def risk_sentence(row: dict[str, Any]) -> str:
    nvd = row.get("nvd", {})
    epss = row.get("epss", {})
    cisa = row.get("cisa", {})
    sev = clean_text(nvd.get("cvss_severity")) or "未提供"
    score = clean_text(nvd.get("cvss_base_score")) or "未提供"
    epss_score = clean_text(epss.get("epss")) or "未提供"
    percentile = clean_text(epss.get("percentile")) or "未提供"
    ransomware = clean_text(cisa.get("knownRansomwareCampaignUse")) or "Unknown"
    return f"该漏洞已进入 CISA KEV，说明存在已知利用活动；CVSS 严重等级为 {sev}，基础分为 {score}；EPSS 分数为 {epss_score}，百分位为 {percentile}；已知勒索软件活动标记为 {ransomware}。"


def repair_sentence(row: dict[str, Any]) -> str:
    action = clean_text(row.get("cisa", {}).get("requiredAction"))
    if not action:
        action = "参考厂商公告和 NVD/CVE 记录，优先进行补丁、缓解配置和日志排查。"
    due = clean_text(row.get("cisa", {}).get("dueDate"))
    if due:
        return f"建议处置：{action} CISA 要求的修复截止日期为 {due}。"
    return f"建议处置：{action}"


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


def build_for_vuln(row: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rid = row["record_id"]
    cve = row.get("cve_id", "")
    title = row.get("title", cve)
    cisa = row.get("cisa", {})
    nvd = row.get("nvd", {})
    refs = source_refs(row)
    desc = clean_text(nvd.get("nvd_description")) or clean_text(cisa.get("shortDescription")) or clean_text(row.get("text"))
    cwe = ", ".join(nvd.get("cwe") or cisa.get("cwes") or []) or "未提供"
    vendor = clean_text(cisa.get("vendorProject")) or "未提供"
    product = clean_text(cisa.get("product")) or "未提供"
    context = cve_context(row)

    qas = [
        qa(rid, "vulnerability_summary", f"{cve} 是什么漏洞？", f"{cve} 是 {title}。{desc}", refs),
        qa(rid, "affected_product", f"{cve} 影响哪个厂商或产品？", f"根据 CISA KEV 记录，厂商/项目为 {vendor}，产品为 {product}。", refs),
        qa(rid, "risk_assessment", f"如何评估 {cve} 的利用风险？", risk_sentence(row), refs),
        qa(rid, "mitigation", f"{cve} 应该如何处置？", repair_sentence(row), refs),
        qa(rid, "weakness_extraction", f"从记录中提取 {cve} 的 CWE 或弱点类型。", f"该记录关联的 CWE/弱点类型为：{cwe}。", refs),
    ]

    sfts = [
        sft(rid, "summarize_vulnerability", "根据给定漏洞记录，用中文总结漏洞影响。", context, f"{cve} 是 {title}。{desc} {risk_sentence(row)}", refs),
        sft(rid, "recommend_mitigation", "根据给定漏洞记录，给出处置建议。", context, repair_sentence(row), refs),
        sft(rid, "extract_structured_fields", "从漏洞记录中抽取 CVE、厂商、产品、严重等级、CWE 和 EPSS。", context, json.dumps({
            "cve_id": cve,
            "vendor": vendor,
            "product": product,
            "cvss_severity": nvd.get("cvss_severity"),
            "cvss_base_score": nvd.get("cvss_base_score"),
            "cwe": nvd.get("cwe") or cisa.get("cwes"),
            "epss": row.get("epss", {}).get("epss"),
            "epss_percentile": row.get("epss", {}).get("percentile"),
            "known_exploited": True,
        }, ensure_ascii=False), refs),
    ]
    return qas, sfts


def build_for_dataset(row: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rid = row["record_id"]
    title = row.get("title", rid)
    text = clean_text(row.get("text"))
    refs = source_refs(row)
    answer = f"{title} 是网络安全/入侵检测相关数据集资料。{text[:600]}"
    qas = [
        qa(rid, "dataset_description", f"{title} 可以用于什么网络安全任务？", answer, refs),
        qa(rid, "dataset_use", f"为什么 {title} 不能直接等同于问答训练语料？", "这类数据集主要提供流量、特征、标签或数据集说明，更适合入侵检测、流量分类或作为背景知识来源；若要用于大模型训练，通常还需要转写为问答、指令或解释样本。", refs),
    ]
    sfts = [
        sft(rid, "dataset_to_training_plan", "根据数据集说明，说明它在网络安全大模型语料构建中的作用。", text, f"{title} 可作为网络安全数据源或背景知识来源，但不能直接作为最终 SFT 语料。建议先抽取任务、字段、攻击类型和标签，再构造问答、解释、分类或处置建议样本。", refs)
    ]
    return qas, sfts


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
        if row.get("record_type") == "vulnerability_text":
            qas, sfts = build_for_vuln(row)
        else:
            qas, sfts = build_for_dataset(row)
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
        "本版 V1 训练语料没有让大模型自由生成事实，而是从 CISA KEV、NVD、FIRST EPSS 和 CVEProject cvelistV5 的结构化字段中模板化生成。这样可以降低幻觉风险，并保证问题、答案、指令输出都能追溯到原始来源。",
        "",
        "五、适用性说明",
        "--------------",
        "这些样本已经比原始数据库记录更接近大模型训练格式：QA 文件适合问答训练或检索问答评估，SFT 文件适合指令微调格式。但由于样本量仍较小，它目前是 V1 样例语料，不适合直接训练完整模型，只适合验证流水线、报告展示和小规模微调冒烟测试。",
        "",
        "六、后续优化方向",
        "----------------",
        "1. 扩大 CVE 数量，例如每类 CWE 或每种严重等级采样 50-100 条。",
        "2. 引入 DeepSeek 只做语言润色或多样化提问，但答案事实仍必须由结构化字段约束。",
        "3. 增加人工抽检字段：事实正确性、答案完整性、是否包含幻觉、是否泄露无关信息。",
        "4. 拆分 train/dev/test，并记录随机种子和数据版本。",
        "5. 加入更多任务类型，例如漏洞分类、风险排序、处置步骤生成、日志解释和 IOC 提取。",
        "",
    ]
    REPORT_OUT.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps(metadata, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
