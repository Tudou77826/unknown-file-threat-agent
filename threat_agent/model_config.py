from __future__ import annotations

import os
from pathlib import Path

from langchain_openai import ChatOpenAI
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def build_chat_model():
    """Build an OpenAI-compatible chat model without embedding credentials."""

    # The project-local file is the deliberate configuration source. Override
    # stale values inherited by long-running IDE/debugger processes.
    load_dotenv(PROJECT_ROOT / ".env", override=True)
    api_key = os.getenv("THREAT_AGENT_API_KEY") or os.getenv("SILICONFLOW_API_KEY")
    base_url = os.getenv("THREAT_AGENT_API_BASE", "https://api.siliconflow.cn/v1")
    model_name = os.getenv("MODEL_NAME")
    if not api_key or not base_url or not model_name:
        raise RuntimeError(
            "Deep Agents mode requires THREAT_AGENT_API_KEY or "
            "SILICONFLOW_API_KEY; THREAT_AGENT_API_BASE optionally overrides "
            "the SiliconFlow OpenAI-compatible endpoint; MODEL_NAME selects "
            "the model"
        )
    return ChatOpenAI(
        model=model_name,
        api_key=api_key,
        base_url=base_url,
        temperature=0,
        max_tokens=512,
        timeout=240,
        max_retries=2,
        model_kwargs={"response_format": {"type": "json_object"}},
    )
