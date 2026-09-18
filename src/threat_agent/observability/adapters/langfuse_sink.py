"""Langfuse trace sink. Optional dependency: importing this module without
``langfuse`` installed raises ImportError, which the factory converts into a
NullTraceSink degradation. Credentials come from the langfuse library's own
environment (LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY / LANGFUSE_HOST)."""

from __future__ import annotations

from typing import Any


class LangfuseTraceSink:
    def __init__(self):
        from langfuse.langchain import CallbackHandler

        self._handler_cls = CallbackHandler

    def handler_for(
        self,
        *,
        tenant_id: str,
        case_id: str,
        run_id: str,
        session_key: str,
        tags: list[str],
    ) -> Any:
        return self._handler_cls(
            session_id=session_key,
            user_id=tenant_id,
            trace_name=f"investigation/{run_id}",
            tags=tags,
            metadata={"tenant_id": tenant_id, "case_id": case_id, "run_id": run_id},
        )

    def close(self) -> None:
        try:
            import langfuse

            langfuse.get_client().flush()
        except Exception:
            pass
