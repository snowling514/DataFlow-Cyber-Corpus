from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS_DIR = ROOT / "cyber_training_corpus_v1"

RAW_FILE = "cyber_corpus_v1_raw_sources.jsonl"
QA_FILE = "cyber_corpus_v1_qa.jsonl"
SFT_FILE = "cyber_corpus_v1_sft.jsonl"
DEFAULT_OUTPUT = "quality_metrics.json"

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", flags=re.I)
CYBER_TERMS = [
    "cve",
    "cwe",
    "cvss",
    "epss",
    "vulnerability",
    "exploit",
    "attack",
    "ransomware",
    "malware",
    "phishing",
    "xss",
    "sql injection",
    "rce",
    "remote code execution",
    "privilege",
    "authentication",
    "patch",
    "mitigation",
    "incident",
    "threat",
    "ioc",
    "漏洞",
    "攻击",
    "风险",
    "修复",
    "补丁",
    "处置",
    "提权",
]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSONL at {path}:{line_no}: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(f"JSONL row must be an object at {path}:{line_no}")
        rows.append(data)
    return rows



def repo_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)

def clean_text(value: Any) -> str:
    return "" if value is None else re.sub(r"\s+", " ", str(value)).strip()


def text_for_row(row: dict[str, Any], fields: list[str]) -> str:
    return " ".join(clean_text(row.get(field)) for field in fields)


def required_field_report(rows: list[dict[str, Any]], fields: list[str]) -> dict[str, Any]:
    missing = Counter()
    for row in rows:
        for field in fields:
            if not clean_text(row.get(field)):
                missing[field] += 1
    return {
        "required_fields": fields,
        "missing_counts": dict(missing),
        "complete_count": len(rows) - sum(1 for row in rows if any(not clean_text(row.get(field)) for field in fields)),
        "complete_ratio": round(
            (len(rows) - sum(1 for row in rows if any(not clean_text(row.get(field)) for field in fields))) / len(rows),
            4,
        ) if rows else 0,
    }


def id_report(rows: list[dict[str, Any]], id_field: str = "id") -> dict[str, Any]:
    ids = [clean_text(row.get(id_field)) for row in rows]
    missing = sum(1 for value in ids if not value)
    non_empty = [value for value in ids if value]
    duplicates = [value for value, count in Counter(non_empty).items() if count > 1]
    return {
        "id_field": id_field,
        "missing_id_count": missing,
        "unique_id_count": len(set(non_empty)),
        "duplicate_id_count": len(non_empty) - len(set(non_empty)),
        "duplicate_ids": duplicates[:20],
    }


def length_report(rows: list[dict[str, Any]], fields: list[str]) -> dict[str, Any]:
    lengths = [len(text_for_row(row, fields)) for row in rows]
    return {
        "min_chars": min(lengths) if lengths else 0,
        "max_chars": max(lengths) if lengths else 0,
        "avg_chars": round(sum(lengths) / len(lengths), 2) if lengths else 0,
        "too_short_count": sum(1 for value in lengths if value < 20),
        "too_long_count": sum(1 for value in lengths if value > 4000),
    }


def cybersecurity_coverage(rows: list[dict[str, Any]], fields: list[str]) -> dict[str, Any]:
    hit_counts = Counter()
    row_hits = 0
    cve_mentions = 0
    for row in rows:
        text = text_for_row(row, fields).lower()
        hits = [term for term in CYBER_TERMS if term.lower() in text]
        if hits:
            row_hits += 1
        hit_counts.update(hits)
        if CVE_PATTERN.search(text):
            cve_mentions += 1
    return {
        "covered_row_count": row_hits,
        "covered_ratio": round(row_hits / len(rows), 4) if rows else 0,
        "cve_mention_count": cve_mentions,
        "top_terms": dict(hit_counts.most_common(20)),
    }


def record_link_report(rows: list[dict[str, Any]], valid_record_ids: set[str]) -> dict[str, Any]:
    missing_record_id = 0
    invalid_record_id = []
    source_ref_count = 0
    for row in rows:
        record_id = clean_text(row.get("record_id"))
        if not record_id:
            missing_record_id += 1
        elif record_id not in valid_record_ids:
            invalid_record_id.append(record_id)
        refs = row.get("source_refs")
        if isinstance(refs, dict) and refs:
            source_ref_count += 1
    return {
        "missing_record_id_count": missing_record_id,
        "invalid_record_id_count": len(invalid_record_id),
        "invalid_record_ids": sorted(set(invalid_record_id))[:20],
        "source_ref_count": source_ref_count,
        "source_ref_ratio": round(source_ref_count / len(rows), 4) if rows else 0,
    }


def corpus_report(name: str, rows: list[dict[str, Any]], required_fields: list[str], text_fields: list[str]) -> dict[str, Any]:
    return {
        "name": name,
        "count": len(rows),
        "ids": id_report(rows),
        "required_fields": required_field_report(rows, required_fields),
        "length": length_report(rows, text_fields),
        "task_type_counts": dict(Counter(clean_text(row.get("task_type") or "unknown") for row in rows)),
        "generation_model_counts": dict(Counter(clean_text(row.get("generation_model") or "not_recorded") for row in rows)),
        "cybersecurity_coverage": cybersecurity_coverage(rows, text_fields),
    }


def build_metrics(corpus_dir: Path) -> dict[str, Any]:
    raw_rows = read_jsonl(corpus_dir / RAW_FILE)
    qa_rows = read_jsonl(corpus_dir / QA_FILE)
    sft_rows = read_jsonl(corpus_dir / SFT_FILE)
    valid_record_ids = {clean_text(row.get("record_id")) for row in raw_rows if clean_text(row.get("record_id"))}

    qa_report = corpus_report("qa", qa_rows, ["id", "record_id", "task_type", "question", "answer"], ["question", "answer"])
    sft_report = corpus_report("sft", sft_rows, ["id", "record_id", "task_type", "instruction", "input", "output"], ["instruction", "input", "output"])
    raw_report = corpus_report("raw_sources", raw_rows, ["record_id", "record_type", "title", "text"], ["title", "text"])
    raw_report["ids"] = id_report(raw_rows, "record_id")

    qa_report["record_links"] = record_link_report(qa_rows, valid_record_ids)
    sft_report["record_links"] = record_link_report(sft_rows, valid_record_ids)

    hard_failures = []
    for section in [raw_report, qa_report, sft_report]:
        if section["ids"]["missing_id_count"] or section["ids"]["duplicate_id_count"]:
            hard_failures.append(f"{section['name']}: id missing or duplicate")
        if section["required_fields"]["complete_ratio"] < 1:
            hard_failures.append(f"{section['name']}: required fields incomplete")
        if section["cybersecurity_coverage"]["covered_ratio"] < 0.8:
            hard_failures.append(f"{section['name']}: cybersecurity term coverage below 0.8")
    for section in [qa_report, sft_report]:
        if section["record_links"]["invalid_record_id_count"]:
            hard_failures.append(f"{section['name']}: invalid record links")
        if section["record_links"]["source_ref_ratio"] < 0.8:
            hard_failures.append(f"{section['name']}: source reference coverage below 0.8")

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "corpus_dir": repo_path(corpus_dir),
        "files": {
            "raw_sources": repo_path(corpus_dir / RAW_FILE),
            "qa": repo_path(corpus_dir / QA_FILE),
            "sft": repo_path(corpus_dir / SFT_FILE),
        },
        "reports": {
            "raw_sources": raw_report,
            "qa": qa_report,
            "sft": sft_report,
        },
        "summary": {
            "raw_source_count": len(raw_rows),
            "qa_count": len(qa_rows),
            "sft_count": len(sft_rows),
            "hard_failure_count": len(hard_failures),
            "hard_failures": hard_failures,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate QA/SFT cybersecurity corpus quality.")
    parser.add_argument("--corpus-dir", default=str(DEFAULT_CORPUS_DIR), help="目录内应包含 raw_sources、qa、sft 三个 JSONL 文件。")
    parser.add_argument("--output", help="评估结果 JSON 输出路径，默认写入语料目录 quality_metrics.json。")
    args = parser.parse_args()

    corpus_dir = Path(args.corpus_dir)
    output_path = Path(args.output) if args.output else corpus_dir / DEFAULT_OUTPUT
    metrics = build_metrics(corpus_dir)
    output_path.write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(metrics["summary"], ensure_ascii=False, indent=2))
    print(f"Quality metrics written to: {output_path}")


if __name__ == "__main__":
    main()

