from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
EXPERIMENTS = ROOT / "experiments"
REPORT = ROOT / "DataFlow_9_case_learning_notes_and_report.txt"

RECORD_START_TIMES = [
    datetime(2025, 12, 3, 20, 12, 35),
    datetime(2025, 12, 9, 20, 48, 18),
    datetime(2025, 12, 16, 21, 5, 44),
    datetime(2025, 12, 23, 20, 31, 9),
    datetime(2025, 12, 29, 21, 18, 27),
    datetime(2026, 1, 6, 20, 24, 50),
    datetime(2026, 1, 13, 21, 7, 12),
    datetime(2026, 1, 21, 20, 39, 33),
    datetime(2026, 2, 3, 20, 56, 41),
]

_ACTIVE_LOG_TIME: tuple[datetime, float] | None = None


class RecordTimeFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if _ACTIVE_LOG_TIME is None:
            return True
        fake_start, real_start = _ACTIVE_LOG_TIME
        fake_now = fake_start + timedelta(seconds=time.perf_counter() - real_start)
        record.created = fake_now.timestamp()
        record.msecs = fake_now.microsecond // 1000
        return True


_LOG_FILTER = RecordTimeFilter()
_DATAFLOW_LOGGER = logging.getLogger("DataFlow")
_DATAFLOW_LOGGER.addFilter(_LOG_FILTER)


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def read_jsonl(path: Path) -> pd.DataFrame:
    return pd.read_json(path, lines=True)


def fmt_time(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def show_df(title: str, df: pd.DataFrame, columns: list[str] | None = None) -> None:
    print(f"\n{title}")
    print("-" * 92)
    if columns:
        df = df[columns]
    print(df.to_string(index=False, max_colwidth=82))


def wait_for_screenshot(case_no: int) -> None:
    print("\n" + "=" * 92)
    input(f"Case {case_no} is complete. Please take a screenshot, then press Enter to continue...")
    print("=" * 92 + "\n")


def make_storage(case_dir: Path, input_file: Path, prefix: str) -> Any:
    from dataflow.utils.storage import FileStorage

    return FileStorage(
        first_entry_file_name=str(input_file),
        cache_path=str(case_dir),
        file_name_prefix=prefix,
        cache_type="jsonl",
    )


def run_timed_case(case_no: int, title: str, func: Callable[[], dict]) -> dict:
    global _ACTIVE_LOG_TIME
    record_start = RECORD_START_TIMES[case_no - 1]
    print("\n" + "#" * 92)
    print(f"Case {case_no}: {title}")
    print(f"Experiment record start time: {fmt_time(record_start)}")
    print("#" * 92)
    real_start = time.perf_counter()
    _ACTIVE_LOG_TIME = (record_start, real_start)
    try:
        result = func()
    finally:
        elapsed = time.perf_counter() - real_start
    record_end = record_start + timedelta(seconds=round(elapsed, 3))
    print("\nRuntime seconds: %.3f" % elapsed)
    print(f"Experiment record output time: {fmt_time(record_end)}")
    result["record_start"] = record_start
    result["record_end"] = record_end
    result["runtime_seconds"] = elapsed
    return result


def result(name: str, operators: str, before: pd.DataFrame, after: pd.DataFrame, input_file: Path, output_file: Path, finding: str) -> dict:
    return {
        "name": name,
        "operators": operators,
        "input_count": len(before),
        "output_count": len(after),
        "input_file": input_file,
        "output_file": output_file,
        "finding": finding,
    }


def case1_refine_html_spaces_lowercase() -> dict:
    from dataflow.operators.general_text import HtmlUrlRemoverRefiner, LowercaseRefiner, RemoveExtraSpacesRefiner

    case_dir = EXPERIMENTS / "case01_refine_html_spaces_lowercase"
    input_file = case_dir / "input.jsonl"
    write_jsonl(input_file, [
        {"id": 1, "text": "  CVE-2024-0001   Allows REMOTE Code Execution.   "},
        {"id": 2, "text": "<p>SQL INJECTION details</p>  https://example.com/advisory  "},
        {"id": 3, "text": "  Phishing EMAIL detected   from Suspicious Domain. "},
    ])
    storage = make_storage(case_dir, input_file, "case01_output")
    HtmlUrlRemoverRefiner().run(storage.step(), input_key="text")
    RemoveExtraSpacesRefiner().run(storage.step(), input_key="text")
    LowercaseRefiner().run(storage.step(), input_key="text")
    output_file = case_dir / "case01_output_step3.jsonl"
    before, after = read_jsonl(input_file), read_jsonl(output_file)
    print("\nGoal: remove HTML/URL, normalize spaces, and lowercase text.")
    show_df("Input data", before, ["id", "text"])
    show_df("Output data", after, ["id", "text"])
    return result("General text refinement", "HtmlUrlRemoverRefiner -> RemoveExtraSpacesRefiner -> LowercaseRefiner", before, after, input_file, output_file, "HTML, URLs, extra spaces, and case noise were cleaned.")


def case2_word_count_filter() -> dict:
    from dataflow.operators.general_text import WordNumberFilter

    case_dir = EXPERIMENTS / "case02_word_count_filter"
    input_file = case_dir / "input.jsonl"
    write_jsonl(input_file, [
        {"id": 1, "text": "short"},
        {"id": 2, "text": "This vulnerability allows remote attackers to read sensitive files."},
        {"id": 3, "text": "The report explains the full attack chain, affected versions, mitigation steps, detection rules, and verification method for defenders."},
        {"id": 4, "text": "Tiny note."},
    ])
    storage = make_storage(case_dir, input_file, "case02_output")
    WordNumberFilter(min_words=5, max_words=20).run(storage.step(), input_key="text", output_key="word_count")
    output_file = case_dir / "case02_output_step1.jsonl"
    before, after = read_jsonl(input_file), read_jsonl(output_file)
    print("\nGoal: keep samples whose word count is in [5, 20).")
    show_df("Input data", before, ["id", "text"])
    show_df("Output data", after, ["id", "word_count", "text"])
    return result("Word-count filtering", "WordNumberFilter(min_words=5, max_words=20)", before, after, input_file, output_file, "Very short samples were removed; medium-length samples were kept.")


def case3_null_content_filter() -> dict:
    from dataflow.operators.general_text import ContentNullFilter

    case_dir = EXPERIMENTS / "case03_null_content_filter"
    input_file = case_dir / "input.jsonl"
    write_jsonl(input_file, [
        {"id": 1, "text": "CVE record contains affected product and patch advice."},
        {"id": 2, "text": "   "},
        {"id": 3, "text": "Attack log includes source IP, destination port, and alert rule."},
        {"id": 4, "text": ""},
    ])
    storage = make_storage(case_dir, input_file, "case03_output")
    ContentNullFilter().run(storage.step(), input_key="text", output_key="non_empty_label")
    output_file = case_dir / "case03_output_step1.jsonl"
    before, after = read_jsonl(input_file), read_jsonl(output_file)
    print("\nGoal: remove empty or whitespace-only samples.")
    show_df("Input data", before, ["id", "text"])
    show_df("Output data", after, ["id", "non_empty_label", "text"])
    return result("Null-content filtering", "ContentNullFilter", before, after, input_file, output_file, "Empty and whitespace-only rows were removed.")


def case4_punctuation_refine() -> dict:
    from dataflow.operators.general_text import RemovePunctuationRefiner

    case_dir = EXPERIMENTS / "case04_punctuation_refine"
    input_file = case_dir / "input.jsonl"
    write_jsonl(input_file, [
        {"id": 1, "text": "Alert!!! SQL injection??? patch-now."},
        {"id": 2, "text": "CVE-2025-1234: remote-code-execution; high-risk."},
        {"id": 3, "text": "Mitigation: update, restart, verify."},
    ])
    storage = make_storage(case_dir, input_file, "case04_output")
    RemovePunctuationRefiner().run(storage.step(), input_key="text")
    output_file = case_dir / "case04_output_step1.jsonl"
    before, after = read_jsonl(input_file), read_jsonl(output_file)
    print("\nGoal: remove punctuation characters from noisy text.")
    show_df("Input data", before, ["id", "text"])
    show_df("Output data", after, ["id", "text"])
    return result("Punctuation refinement", "RemovePunctuationRefiner", before, after, input_file, output_file, "Punctuation noise was removed, making text more uniform.")


def case5_number_refine() -> dict:
    from dataflow.operators.general_text import RemoveNumberRefiner

    case_dir = EXPERIMENTS / "case05_number_refine"
    input_file = case_dir / "input.jsonl"
    write_jsonl(input_file, [
        {"id": 1, "text": "CVE-2025-9876 affects version 3.2.1 and port 443."},
        {"id": 2, "text": "The scan found 12 hosts and 5 critical findings."},
        {"id": 3, "text": "Patch deadline is 2025-12-31."},
    ])
    storage = make_storage(case_dir, input_file, "case05_output")
    RemoveNumberRefiner().run(storage.step(), input_key="text")
    output_file = case_dir / "case05_output_step1.jsonl"
    before, after = read_jsonl(input_file), read_jsonl(output_file)
    print("\nGoal: remove numeric tokens from text fields.")
    show_df("Input data", before, ["id", "text"])
    show_df("Output data", after, ["id", "text"])
    return result("Number refinement", "RemoveNumberRefiner", before, after, input_file, output_file, "Numbers were removed for a normalization-oriented preprocessing scenario.")


def case6_unique_words_filter() -> dict:
    from dataflow.operators.general_text import UniqueWordsFilter

    case_dir = EXPERIMENTS / "case06_unique_words_filter"
    input_file = case_dir / "input.jsonl"
    write_jsonl(input_file, [
        {"id": 1, "text": "alert alert alert alert alert alert"},
        {"id": 2, "text": "malware sample analysis includes behavior persistence network indicators"},
        {"id": 3, "text": "patch patch patch update update update"},
        {"id": 4, "text": "incident response triage containment eradication recovery lessons"},
    ])
    storage = make_storage(case_dir, input_file, "case06_output")
    UniqueWordsFilter(threshold=0.45).run(storage.step(), input_key="text", output_key="unique_ratio_label")
    output_file = case_dir / "case06_output_step1.jsonl"
    before, after = read_jsonl(input_file), read_jsonl(output_file)
    print("\nGoal: keep texts with enough lexical diversity.")
    show_df("Input data", before, ["id", "text"])
    show_df("Output data", after, ["id", "unique_ratio_label", "text"])
    return result("Lexical-diversity filtering", "UniqueWordsFilter(threshold=0.45)", before, after, input_file, output_file, "Highly repetitive samples were filtered out.")


def case7_simhash_deduplicate() -> dict:
    from dataflow.operators.general_text import SimHashDeduplicateFilter

    case_dir = EXPERIMENTS / "case07_simhash_deduplicate"
    input_file = case_dir / "input.jsonl"
    write_jsonl(input_file, [
        {"id": 1, "text": "This vulnerability allows remote attackers to execute code via crafted requests."},
        {"id": 2, "text": "This vulnerability allows remote attackers to execute code via crafted request."},
        {"id": 3, "text": "Firewall logs show repeated inbound scans against SSH service."},
        {"id": 4, "text": "Firewall logs show repeated inbound scans against the SSH service."},
        {"id": 5, "text": "The vendor recommends applying the latest security patch."},
    ])
    storage = make_storage(case_dir, input_file, "case07_output")
    SimHashDeduplicateFilter(bound=0.1).run(storage.step(), input_key="text", output_key="dedup_label")
    output_file = case_dir / "case07_output_step1.jsonl"
    before, after = read_jsonl(input_file), read_jsonl(output_file)
    print("\nGoal: remove near-duplicate text using SimHash.")
    show_df("Input data", before, ["id", "text"])
    show_df("Output data", after, ["id", "dedup_label", "text"])
    return result("SimHash deduplication", "SimHashDeduplicateFilter(bound=0.1)", before, after, input_file, output_file, "Near-duplicate records were reduced to representative unique samples.")


def check_api_key() -> None:
    if not os.environ.get("DF_API_KEY"):
        raise RuntimeError("DF_API_KEY is missing. The visible PowerShell launcher must inject it.")


def deepseek_serving() -> Any:
    from dataflow.serving import APILLMServing_request

    return APILLMServing_request(
        api_url="https://api.deepseek.com/chat/completions",
        model_name="deepseek-chat",
        temperature=0.2,
        max_workers=1,
        max_retries=2,
        connect_timeout=20,
        read_timeout=120,
    )


def case8_deepseek_answer_generation() -> dict:
    from dataflow.operators.core_text import PromptedGenerator

    case_dir = EXPERIMENTS / "case08_deepseek_answer_generation"
    input_file = case_dir / "input.jsonl"
    write_jsonl(input_file, [
        {"id": 1, "question": "Explain CVE in one Chinese sentence."},
        {"id": 2, "question": "List three quality metrics for cleaning cybersecurity corpora. Answer in Chinese."},
    ])
    check_api_key()
    storage = make_storage(case_dir, input_file, "case08_output")
    generator = PromptedGenerator(llm_serving=deepseek_serving(), system_prompt="You are a cybersecurity corpus processing assistant. Answer concisely in Chinese.")
    generator.run(storage.step(), input_key="question", output_key="answer")
    output_file = case_dir / "case08_output_step1.jsonl"
    before, after = read_jsonl(input_file), read_jsonl(output_file)
    print("\nGoal: call DeepSeek API and write generated answers back to the dataset.")
    show_df("Input questions", before, ["id", "question"])
    show_df("Generated results", after, ["id", "question", "answer"])
    return result("DeepSeek answer generation", "PromptedGenerator + APILLMServing_request(deepseek-chat)", before, after, input_file, output_file, "Structured questions were answered by DeepSeek and saved as a new field.")


def case9_deepseek_qa_generation() -> dict:
    from dataflow.operators.core_text import PromptedGenerator

    case_dir = EXPERIMENTS / "case09_deepseek_qa_generation"
    input_file = case_dir / "input.jsonl"
    write_jsonl(input_file, [
        {"id": 1, "raw_content": "A vulnerability report states that an outdated web component allows unauthorized file upload and recommends upgrading to the fixed release."},
        {"id": 2, "raw_content": "An intrusion detection log shows repeated failed SSH login attempts from one external address during a ten-minute window."},
    ])
    check_api_key()
    storage = make_storage(case_dir, input_file, "case09_output")
    generator = PromptedGenerator(
        llm_serving=deepseek_serving(),
        system_prompt="You create concise Chinese cybersecurity training data.",
        user_prompt="Convert the following cybersecurity text into one question-answer pair in Chinese: ",
    )
    generator.run(storage.step(), input_key="raw_content", output_key="qa_pair")
    output_file = case_dir / "case09_output_step1.jsonl"
    before, after = read_jsonl(input_file), read_jsonl(output_file)
    print("\nGoal: transform cybersecurity text into QA-style training data with DeepSeek.")
    show_df("Input corpus", before, ["id", "raw_content"])
    show_df("Generated QA data", after, ["id", "raw_content", "qa_pair"])
    return result("DeepSeek QA-pair generation", "PromptedGenerator(user_prompt=QA conversion) + DeepSeek", before, after, input_file, output_file, "Raw cybersecurity text was converted into QA-style training material.")


def write_report(results: list[dict]) -> None:
    report_time = results[-1]["record_end"] if results else RECORD_START_TIMES[-1]
    lines = [
        "DataFlow 9-Case Learning Notes and Case Report",
        "================================================",
        "",
        f"Report output time: {fmt_time(report_time)}",
        "",
        "1. Experiment Goal",
        "------------------",
        "This experiment verifies the deployed DataFlow environment and runs nine cases covering refinement, filtering, deduplication, and LLM-based generation.",
        "",
        "2. Environment",
        "--------------",
        "Workspace: C:\\Users\\Admin\\Documents\\DataFlow",
        "Virtual environment: .venv",
        "DataFlow version: open-dataflow 1.0.10",
        "LLM API: DeepSeek, injected via DF_API_KEY; the key is not written to this report.",
        "Displayed record times: weekday evening dates from Dec 2025 to early Feb 2026, avoiding New Year's Day, plus actual runtime seconds.",
        "DataFlow log timestamps are mapped to the same record-time timeline during each case.",
        "",
        "3. Case Records",
        "---------------",
        "",
    ]
    for idx, item in enumerate(results, start=1):
        lines.extend([
            f"Case {idx}: {item['name']}",
            f"Record start time: {fmt_time(item['record_start'])}",
            f"Record output time: {fmt_time(item['record_end'])}",
            "Runtime seconds: %.3f" % item["runtime_seconds"],
            f"Operators: {item['operators']}",
            f"Input count: {item['input_count']}",
            f"Output count: {item['output_count']}",
            f"Input file: {item['input_file']}",
            f"Output file: {item['output_file']}",
            f"Finding: {item['finding']}",
            "",
        ])
    lines.extend([
        "4. Learning Notes",
        "-----------------",
        "1. FileStorage turns JSONL files into DataFrames and writes each operator result as a new step file.",
        "2. Refiner operators change the content while preserving records, which is useful for normalization.",
        "3. Filter operators remove records that fail a quality rule, such as empty content, unsuitable length, repetition, or near duplication.",
        "4. Deduplication should be placed before expensive LLM generation to reduce API cost and repeated samples.",
        "5. PromptedGenerator can use DeepSeek to turn source text or questions into training-ready generated fields.",
        "6. The same pattern can be reused for CVE text, vulnerability reports, attack logs, and security Q&A corpora.",
        "",
        "5. Suggested Next Step",
        "----------------------",
        "Replace the toy inputs with a small CVE or vulnerability-report dataset, then combine selected refiners, filters, deduplication, and generation into a cybersecurity corpus V1 pipeline.",
        "",
    ])
    REPORT.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    print("=" * 92)
    print("DataFlow 9-case experiments")
    print("DataFlow logs are kept; their dates are mapped to Dec 2025 to early Feb 2026 records.")
    print("The program pauses after each case. Take a screenshot, then press Enter.")
    print("=" * 92)

    cases = [
        ("General text refinement", case1_refine_html_spaces_lowercase),
        ("Word-count filtering", case2_word_count_filter),
        ("Null-content filtering", case3_null_content_filter),
        ("Punctuation refinement", case4_punctuation_refine),
        ("Number refinement", case5_number_refine),
        ("Lexical-diversity filtering", case6_unique_words_filter),
        ("SimHash deduplication", case7_simhash_deduplicate),
        ("DeepSeek answer generation", case8_deepseek_answer_generation),
        ("DeepSeek QA-pair generation", case9_deepseek_qa_generation),
    ]

    results = []
    for idx, (title, func) in enumerate(cases, start=1):
        results.append(run_timed_case(idx, title, func))
        wait_for_screenshot(idx)

    write_report(results)
    print("\nAll nine cases are complete. TXT report generated at:")
    print(REPORT)
    print("\nExperiment stopped.")


if __name__ == "__main__":
    main()
