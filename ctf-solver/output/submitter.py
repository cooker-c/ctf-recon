from __future__ import annotations

from typing import Optional

import requests

from core.messages import SubmissionResult
from utils.logger import get_logger

log = get_logger(__name__)


def submit_flag(flag: str, submit_url: str, token: Optional[str] = None) -> SubmissionResult:
    headers = {"User-Agent": "ctf-agent/0.1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = requests.post(submit_url, json={"flag": flag}, headers=headers, timeout=15)
        return SubmissionResult(
            submitted=resp.ok,
            flag=flag,
            response_status=resp.status_code,
            response_body=resp.text,
            error=None if resp.ok else resp.text,
        )
    except Exception as exc:  # noqa: BLE001
        log.error("Flag submission failed: %s", exc)
        return SubmissionResult(submitted=False, flag=flag, response_status=None, response_body=None, error=str(exc))
