from __future__ import annotations

import json
import os
import re
import time
from typing import Any

import requests

DEEPSEEK_API_URL = "https://api.deepseek.com/chat/completions"
DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")


def require_api_key() -> str:
    api_key = os.getenv("DF_API_KEY")
    if not api_key:
        raise RuntimeError(
            "DF_API_KEY is not set. Set it before running DeepSeek-powered synthesis, "
            "for example: $env:DF_API_KEY = \"your_deepseek_api_key\""
        )
    return api_key


def _extract_json_object(text: str) -> Any:
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.I)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        start_candidates = [idx for idx in [cleaned.find("{"), cleaned.find("[")] if idx >= 0]
        if not start_candidates:
            raise
        start = min(start_candidates)
        end_obj = cleaned.rfind("}")
        end_arr = cleaned.rfind("]")
        end = max(end_obj, end_arr)
        if end <= start:
            raise
        return json.loads(cleaned[start : end + 1])


def deepseek_chat(system_prompt: str, user_prompt: str, temperature: float = 0.2, max_retries: int = 3) -> str:
    api_key = require_api_key()
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": DEEPSEEK_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": temperature,
    }
    last_error: Exception | None = None
    for attempt in range(max_retries):
        try:
            response = requests.post(DEEPSEEK_API_URL, headers=headers, json=payload, timeout=(20, 180))
            if response.status_code in (429, 500, 502, 503, 504) and attempt < max_retries - 1:
                time.sleep(2 ** attempt + 1)
                continue
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
        except Exception as exc:  # noqa: BLE001 - preserve API failure context for caller
            last_error = exc
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt + 1)
                continue
            raise RuntimeError(f"DeepSeek request failed: {exc}") from exc
    raise RuntimeError(f"DeepSeek request failed: {last_error}")


def deepseek_json(system_prompt: str, user_prompt: str, temperature: float = 0.2) -> Any:
    content = deepseek_chat(system_prompt, user_prompt, temperature=temperature)
    return _extract_json_object(content)


def validate_list_payload(payload: Any, key: str) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or key not in payload:
        raise ValueError(f"DeepSeek response must be a JSON object containing '{key}'.")
    value = payload[key]
    if not isinstance(value, list):
        raise ValueError(f"DeepSeek response field '{key}' must be a list.")
    rows = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError(f"Each item in '{key}' must be an object.")
        rows.append(item)
    return rows
