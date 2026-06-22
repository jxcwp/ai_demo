import json
import os
from typing import Any

import httpx


def _settings() -> dict[str, Any]:
    return {
        "provider": os.getenv("LLM_PROVIDER", "local").lower(),
        "api_key": os.getenv("LLM_API_KEY", ""),
        "model": os.getenv("LLM_MODEL", "gpt-4o-mini"),
        "api_base": os.getenv("LLM_API_BASE", "https://api.openai.com/v1"),
        "timeout": float(os.getenv("LLM_TIMEOUT_SECONDS", "8")),
        "retries": int(os.getenv("LLM_RETRIES", "2")),
    }


def _local_template_script(data: Any, idx: int) -> dict[str, Any]:
    hooks = {
        "restaurant": ["附近吃什么？", "这家店被低估了", "人均不高但很稳"],
        "beauty": ["做完变化太明显了", "学生党也能做", "本周预约快满了"],
    }
    hook = hooks[data.industry][idx % 3]
    return {
        "title": f"{data.business_name}选题{idx + 1}: {hook}",
        "hook_3s": f"{hook}，今天带你看{data.main_offer}",
        "voiceover": f"这里是{data.business_name}，主打{data.main_offer}，适合{data.audience}，人均约{data.avg_ticket}。本期目标：{data.goal}。",
        "shots": ["门头环境", "过程特写", "结果反馈"],
        "duration_sec": 20 + (idx % 3) * 5,
        "cta": "评论区回复关键词，领取到店福利",
    }


def _normalize_script(raw: dict[str, Any], fallback: dict[str, Any]) -> dict[str, Any]:
    shots = raw.get("shots")
    if not isinstance(shots, list) or not all(isinstance(s, str) for s in shots):
        shots = fallback["shots"]

    return {
        "title": str(raw.get("title") or fallback["title"]),
        "hook_3s": str(raw.get("hook_3s") or fallback["hook_3s"]),
        "voiceover": str(raw.get("voiceover") or fallback["voiceover"]),
        "shots": shots,
        "duration_sec": int(raw.get("duration_sec") or fallback["duration_sec"]),
        "cta": str(raw.get("cta") or fallback["cta"]),
    }


def _call_openai_provider(data: Any, idx: int, cfg: dict[str, Any]) -> dict[str, Any]:
    if not cfg["api_key"]:
        raise RuntimeError("LLM_API_KEY is required for remote providers")

    fallback = _local_template_script(data, idx)
    prompt = (
        "请返回一个JSON对象，字段为title/hook_3s/voiceover/shots/cta/duration_sec。"
        "不要输出markdown。"
        f"行业:{data.industry}; 商家:{data.business_name}; 主推:{data.main_offer}; 客单:{data.avg_ticket};"
        f"人群:{data.audience}; 目标:{data.goal}; 序号:{idx + 1}"
    )

    payload = {
        "model": cfg["model"],
        "messages": [
            {"role": "system", "content": "你是短视频脚本助手，只输出JSON。"},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.7,
    }
    headers = {"Authorization": f"Bearer {cfg["api_key"]}", "Content-Type": "application/json"}

    with httpx.Client(timeout=cfg["timeout"]) as client:
        resp = client.post(f"{cfg["api_base"]}/chat/completions", json=payload, headers=headers)
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]

    raw = json.loads(content)
    if not isinstance(raw, dict):
        raise ValueError("Model response is not a JSON object")
    return _normalize_script(raw, fallback)


def generate_script(data: Any, idx: int) -> dict[str, Any]:
    fallback = _local_template_script(data, idx)
    cfg = _settings()
    provider = cfg["provider"]
    if provider in ("local", "template"):
        return fallback

    for _ in range(cfg["retries"] + 1):
        try:
            if provider in ("openai", "openai_compatible"):
                return _call_openai_provider(data, idx, cfg)
            raise RuntimeError(f"Unsupported LLM_PROVIDER: {provider}")
        except Exception:  # noqa: BLE001
            pass

    # 失败降级：回退到本地模板
    return fallback
