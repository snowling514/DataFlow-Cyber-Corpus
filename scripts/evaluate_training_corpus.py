from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from config_utils import load_config, project_path, repo_path

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", flags=re.I)


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


def load_schema(config: dict[str, Any], name: str) -> dict[str, Any]:
    schema_dir = project_path(config["schemas"]["dir"])
    schema_file = config["schemas"]["files"][name]
    schema = json.loads((schema_dir / schema_file).read_text(encoding="utf-8"))
    schema["_schema_file"] = schema_dir / schema_file
    return schema


def clean_text(value: Any) -> str:
    return "" if value is None else re.sub(r"\s+", " ", str(value)).strip()


def text_for_row(row: dict[str, Any], fields: list[str]) -> str:
    return " ".join(clean_text(row.get(field)) for field in fields)


def matches_type(value: Any, expected_type: str, item_type: str | None = None) -> bool:
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "object":
        return isinstance(value, dict)
    if expected_type == "array":
        if not isinstance(value, list):
            return False
        if item_type == "string":
            return all(isinstance(item, str) for item in value)
        return True
    if expected_type == "number":
        return isinstance(value, int | float) and not isinstance(value, bool)
    if expected_type == "boolean":
        return isinstance(value, bool)
    return True


def row_has_schema_issue(row: dict[str, Any], fields: dict[str, Any]) -> bool:
    for field, spec in fields.items():
        value = row.get(field)
        if spec.get("required") and (field not in row or clean_text(value) == ""):
            return True
        if field in row and value is not None and not matches_type(value, spec.get("type", "any"), spec.get("items")):
            return True
    return False


def schema_validation_report(rows: list[dict[str, Any]], schema: dict[str, Any]) -> dict[str, Any]:
    fields = schema.get("fields", {})
    missing_required = Counter()
    type_mismatches = Counter()
    unexpected_fields = Counter()

    allowed_fields = set(fields)
    for row in rows:
        for field, spec in fields.items():
            value = row.get(field)
            if spec.get("required") and (field not in row or clean_text(value) == ""):
                missing_required[field] += 1
                continue
            if field in row and value is not None and not matches_type(value, spec.get("type", "any"), spec.get("items")):
                type_mismatches[field] += 1
        unexpected_fields.update(field for field in row if field not in allowed_fields)

    valid_rows = len(rows) - sum(1 for row in rows if row_has_schema_issue(row, fields))
    return {
        "schema": schema.get("name"),
        "schema_version": schema.get("schema_version"),
        "schema_file": repo_path(schema["_schema_file"]),
        "missing_required_counts": dict(missing_required),
        "type_mismatch_counts": dict(type_mismatches),
        "unexpected_field_counts": dict(unexpected_fields),
        "valid_row_count": valid_rows,
        "valid_ratio": round(valid_rows / len(rows), 4) if rows else 0,
    }


def required_field_report(rows: list[dict[str, Any]], fields: list[str]) -> dict[str, Any]:
    missing = Counter()
    incomplete_rows = 0
    for row in rows:
        row_incomplete = False
        for field in fields:
            if not clean_text(row.get(field)):
                missing[field] += 1
                row_incomplete = True
        if row_incomplete:
            incomplete_rows += 1
    return {
        "required_fields": fields,
        "missing_counts": dict(missing),
        "complete_count": len(rows) - incomplete_rows,
        "complete_ratio": round((len(rows) - incomplete_rows) / len(rows), 4) if rows else 0,
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


def length_report(rows: list[dict[str, Any]], fields: list[str], min_chars: int, max_chars: int) -> dict[str, Any]:
    lengths = [len(text_for_row(row, fields)) for row in rows]
    return {
        "min_chars": min(lengths) if lengths else 0,
        "max_chars": max(lengths) if lengths else 0,
        "avg_chars": round(sum(lengths) / len(lengths), 2) if lengths else 0,
        "too_short_count": sum(1 for value in lengths if value < min_chars),
        "too_long_count": sum(1 for value in lengths if value > max_chars),
        "min_chars_threshold": min_chars,
        "max_chars_threshold": max_chars,
    }


def cybersecurity_coverage(rows: list[dict[str, Any]], fields: list[str], terms: list[str]) -> dict[str, Any]:
    hit_counts = Counter()
    row_hits = 0
    cve_mentions = 0
    for row in rows:
        text = text_for_row(row, fields).lower()
        hits = [term for term in terms if term.lower() in text]
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


def corpus_report(
    name: str,
    rows: list[dict[str, Any]],
    required_fields: list[str],
    text_fields: list[str],
    schema: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    gate = config["quality_gate"]
    return {
        "name": name,
        "count": len(rows),
        "ids": id_report(rows),
        "schema_validation": schema_validation_report(rows, schema),
        "required_fields": required_field_report(rows, required_fields),
        "length": length_report(rows, text_fields, gate["min_chars"], gate["max_chars"]),
        "task_type_counts": dict(Counter(clean_text(row.get("task_type") or "unknown") for row in rows)),
        "generation_model_counts": dict(Counter(clean_text(row.get("generation_model") or "not_recorded") for row in rows)),
        "cybersecurity_coverage": cybersecurity_coverage(rows, text_fields, config["cyber_terms"]),
    }


def build_metrics(corpus_dir: Path, config: dict[str, Any]) -> dict[str, Any]:
    files = config["corpus"]["files"]
    raw_rows = read_jsonl(corpus_dir / files["raw_sources"])
    qa_rows = read_jsonl(corpus_dir / files["qa"])
    sft_rows = read_jsonl(corpus_dir / files["sft"])
    valid_record_ids = {clean_text(row.get("record_id")) for row in raw_rows if clean_text(row.get("record_id"))}

    raw_schema = load_schema(config, "raw_sources")
    qa_schema = load_schema(config, "qa")
    sft_schema = load_schema(config, "sft")

    raw_report = corpus_report("raw_sources", raw_rows, ["record_id", "record_type", "title", "text"], ["title", "text"], raw_schema, config)
    raw_report["ids"] = id_report(raw_rows, "record_id")
    qa_report = corpus_report("qa", qa_rows, ["id", "record_id", "task_type", "question", "answer"], ["question", "answer"], qa_schema, config)
    sft_report = corpus_report("sft", sft_rows, ["id", "record_id", "task_type", "instruction", "input", "output"], ["instruction", "input", "output"], sft_schema, config)

    qa_report["record_links"] = record_link_report(qa_rows, valid_record_ids)
    sft_report["record_links"] = record_link_report(sft_rows, valid_record_ids)

    gate = config["quality_gate"]
    hard_failures = []
    for section in [raw_report, qa_report, sft_report]:
        if section["ids"]["missing_id_count"] or section["ids"]["duplicate_id_count"]:
            hard_failures.append(f"{section['name']}: id missing or duplicate")
        if section["required_fields"]["complete_ratio"] < gate["min_required_complete_ratio"]:
            hard_failures.append(f"{section['name']}: required fields incomplete")
        if section["schema_validation"]["valid_ratio"] < gate["min_schema_valid_ratio"]:
            hard_failures.append(f"{section['name']}: schema validation failed")
        if section["cybersecurity_coverage"]["covered_ratio"] < gate["min_cybersecurity_coverage_ratio"]:
            hard_failures.append(f"{section['name']}: cybersecurity term coverage below threshold")
    for section in [qa_report, sft_report]:
        if section["record_links"]["invalid_record_id_count"]:
            hard_failures.append(f"{section['name']}: invalid record links")
        if section["record_links"]["source_ref_ratio"] < gate["min_source_reference_ratio"]:
            hard_failures.append(f"{section['name']}: source reference coverage below threshold")

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "config_file": repo_path(config["_config_path"]),
        "corpus_dir": repo_path(corpus_dir),
        "schema_dir": repo_path(project_path(config["schemas"]["dir"])),
        "quality_gate": gate,
        "files": {
            "raw_sources": repo_path(corpus_dir / files["raw_sources"]),
            "qa": repo_path(corpus_dir / files["qa"]),
            "sft": repo_path(corpus_dir / files["sft"]),
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
    parser.add_argument("--config", help="流水线配置文件，默认 config/pipeline_config.json。")
    parser.add_argument("--corpus-dir", help="语料目录；默认读取配置中的 corpus.default_dir。")
    parser.add_argument("--output", help="评估结果 JSON 输出路径，默认写入语料目录配置的 quality_metrics 文件。")
    args = parser.parse_args()

    config = load_config(args.config)
    corpus_dir = project_path(args.corpus_dir or config["corpus"]["default_dir"])
    output_path = project_path(args.output) if args.output else corpus_dir / config["corpus"]["files"]["quality_metrics"]
    metrics = build_metrics(corpus_dir, config)
    output_path.write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(metrics["summary"], ensure_ascii=False, indent=2))
    print(f"Quality metrics written to: {output_path}")


if __name__ == "__main__":
    main()
