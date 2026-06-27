from __future__ import annotations

import argparse
import json
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd

from dataflow.operators.general_text import (
    ContentNullFilter,
    HtmlUrlRemoverRefiner,
    RemoveExtraSpacesRefiner,
    SimHashDeduplicateFilter,
    UniqueWordsFilter,
    WordNumberFilter,
)
from dataflow.utils.storage import FileStorage

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS = ROOT / "results"

CYBER_KEYWORDS = [
    "cve", "cwe", "cvss", "epss", "vulnerability", "exploit", "attack",
    "malware", "ransomware", "phishing", "xss", "sql injection", "rce",
    "remote code execution", "privilege", "authentication", "ssh", "firewall",
    "ioc", "indicator", "patch", "mitigation", "port", "payload", "incident",
    "threat", "log", "scan", "backdoor", "credential", "webshell", "risk",
    "severity", "漏洞", "攻击", "恶意软件", "勒索", "钓鱼", "补丁", "修复",
    "端口", "日志", "入侵", "风险", "凭据", "提权", "远程代码执行",
]


def clean_text(value: Any) -> str:
    text = "" if value is None else str(value)
    return re.sub(r"\s+", " ", text).strip()


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_records(args: argparse.Namespace) -> list[dict[str, Any]]:
    if args.text:
        return [{"id": "input_001", "title": args.title or "manual text", "text": args.text, "source_type": "manual_text"}]

    if args.input_file:
        path = Path(args.input_file)
        if not path.exists():
            raise FileNotFoundError(path)
        suffix = path.suffix.lower()
        if suffix == ".jsonl":
            rows = read_jsonl(path)
        elif suffix == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
            rows = data if isinstance(data, list) else [data]
        else:
            raw = path.read_text(encoding="utf-8")
            parts = [p.strip() for p in re.split(r"\n\s*\n", raw) if p.strip()]
            rows = [{"id": f"input_{i:03d}", "title": path.stem, "text": part, "source_type": "text_file"} for i, part in enumerate(parts, 1)]
        return normalize_records(rows)

    print("请输入需要处理的网络安全文本。输入完成后按 Enter，再输入一行 END 结束：")
    lines = []
    while True:
        line = input()
        if line.strip().upper() == "END":
            break
        lines.append(line)
    text = "\n".join(lines).strip()
    if not text:
        raise ValueError("未输入任何内容。")
    return [{"id": "input_001", "title": args.title or "interactive input", "text": text, "source_type": "interactive"}]


def normalize_records(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []
    for i, row in enumerate(rows, 1):
        text = row.get("text") or row.get("description") or row.get("content") or row.get("raw_content") or ""
        normalized.append({
            "id": str(row.get("id") or row.get("record_id") or f"input_{i:03d}"),
            "title": clean_text(row.get("title") or row.get("name") or f"input_{i:03d}"),
            "text": clean_text(text),
            "source_type": clean_text(row.get("source_type") or row.get("type") or "user_file"),
        })
    return normalized


def keyword_hits(text: str) -> list[str]:
    lower = text.lower()
    return sorted({kw for kw in CYBER_KEYWORDS if kw.lower() in lower})


def run_dataflow(raw_file: Path, cache_dir: Path, min_words: int, max_words: int, unique_threshold: float, dedup_bound: float) -> Path:
    storage = FileStorage(
        first_entry_file_name=str(raw_file),
        cache_path=str(cache_dir),
        file_name_prefix="processed",
        cache_type="jsonl",
    )
    HtmlUrlRemoverRefiner().run(storage.step(), input_key="text")
    RemoveExtraSpacesRefiner().run(storage.step(), input_key="text")
    ContentNullFilter().run(storage.step(), input_key="text", output_key="non_empty_label")
    WordNumberFilter(min_words=min_words, max_words=max_words).run(storage.step(), input_key="text", output_key="word_count")
    UniqueWordsFilter(threshold=unique_threshold).run(storage.step(), input_key="text", output_key="unique_word_label")
    SimHashDeduplicateFilter(bound=dedup_bound).run(storage.step(), input_key="text", output_key="dedup_label")
    return cache_dir / "processed_step6.jsonl"


def enrich_processed(path: Path, run_id: str) -> list[dict[str, Any]]:
    df = pd.read_json(path, lines=True)
    rows = []
    for _, row in df.iterrows():
        text = clean_text(row.get("text"))
        hits = keyword_hits(text)
        rows.append({
            "run_id": run_id,
            "id": clean_text(row.get("id")),
            "title": clean_text(row.get("title")),
            "source_type": clean_text(row.get("source_type")),
            "text": text,
            "word_count": int(row.get("word_count", len(text.split()))),
            "cyber_keyword_hits": hits,
            "cyber_keyword_hit_count": len(hits),
            "cyber_related": len(hits) > 0,
            "processing_notes": "html_url_removed; spaces_normalized; non_empty; length_filtered; diversity_filtered; simhash_deduplicated",
        })
    return rows


def make_qa(processed: list[dict[str, Any]]) -> list[dict[str, Any]]:
    qa_rows = []
    for row in processed:
        rid = row["id"]
        title = row["title"] or rid
        hits = "、".join(row["cyber_keyword_hits"]) if row["cyber_keyword_hits"] else "未命中明显安全关键词"
        text = row["text"]
        qa_rows.append({
            "id": f"qa_{rid}_summary",
            "record_id": rid,
            "task_type": "ad_hoc_summary",
            "question": f"这段材料《{title}》主要涉及什么安全问题？",
            "answer": f"该材料的主要内容是：{text[:360]}。关键词命中：{hits}。",
        })
        qa_rows.append({
            "id": f"qa_{rid}_mitigation",
            "record_id": rid,
            "task_type": "ad_hoc_mitigation",
            "question": f"针对《{title}》中的安全问题，可以如何初步处置？",
            "answer": "建议先确认受影响资产和版本，核对厂商公告或漏洞编号，评估利用风险，优先应用补丁或缓解措施，并检查相关日志、账号和网络访问痕迹。",
        })
    return qa_rows


def make_sft(processed: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sft_rows = []
    for row in processed:
        rid = row["id"]
        sft_rows.append({
            "id": f"sft_{rid}_extract_and_summarize",
            "record_id": rid,
            "task_type": "ad_hoc_extract_and_summarize",
            "instruction": "请根据输入的网络安全文本，提取关键词并给出简短总结。",
            "input": row["text"],
            "output": json.dumps({
                "title": row["title"],
                "cyber_related": row["cyber_related"],
                "keywords": row["cyber_keyword_hits"],
                "summary": row["text"][:420],
                "suggested_next_step": "进行来源核验、影响范围确认、修复建议整理和人工抽检。",
            }, ensure_ascii=False),
        })
    return sft_rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Process new cybersecurity text and export results.")
    parser.add_argument("--text", help="直接输入一段需要处理的文本。")
    parser.add_argument("--input-file", help="输入文件，支持 .txt/.json/.jsonl。")
    parser.add_argument("--title", help="手动输入文本的标题。")
    parser.add_argument("--output-dir", default=str(DEFAULT_RESULTS), help="结果输出目录，默认 results。")
    parser.add_argument("--min-words", type=int, default=3, help="最小词数过滤阈值。")
    parser.add_argument("--max-words", type=int, default=400, help="最大词数过滤阈值。")
    parser.add_argument("--unique-threshold", type=float, default=0.20, help="唯一词比例过滤阈值。")
    parser.add_argument("--dedup-bound", type=float, default=0.08, help="SimHash 去重阈值。")
    args = parser.parse_args()

    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.output_dir) / run_id
    cache_dir = out_dir / "cache"
    out_dir.mkdir(parents=True, exist_ok=True)

    raw_records = normalize_records(load_records(args))
    raw_file = out_dir / "input.jsonl"
    write_jsonl(raw_file, raw_records)

    processed_step = run_dataflow(raw_file, cache_dir, args.min_words, args.max_words, args.unique_threshold, args.dedup_bound)
    processed = enrich_processed(processed_step, run_id)
    qa_rows = make_qa(processed)
    sft_rows = make_sft(processed)

    processed_file = out_dir / "processed.jsonl"
    qa_file = out_dir / "qa.jsonl"
    sft_file = out_dir / "sft.jsonl"
    summary_file = out_dir / "summary.json"
    write_jsonl(processed_file, processed)
    write_jsonl(qa_file, qa_rows)
    write_jsonl(sft_file, sft_rows)

    summary = {
        "run_id": run_id,
        "input_count": len(raw_records),
        "processed_count": len(processed),
        "qa_count": len(qa_rows),
        "sft_count": len(sft_rows),
        "output_dir": str(out_dir),
        "files": {
            "input": str(raw_file),
            "processed": str(processed_file),
            "qa": str(qa_file),
            "sft": str(sft_file),
        },
    }
    summary_file.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    latest_dir = Path(args.output_dir)
    for src, name in [(processed_file, "latest_processed.jsonl"), (qa_file, "latest_qa.jsonl"), (sft_file, "latest_sft.jsonl"), (summary_file, "latest_summary.json")]:
        shutil.copyfile(src, latest_dir / name)

    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
