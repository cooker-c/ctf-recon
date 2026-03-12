from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List, Optional

import requests
from bs4 import BeautifulSoup  # type: ignore

from core.messages import AttachmentRecord, ChallengeMetadata
from tools.file_tool import analyze_file
from utils.file_utils import ensure_dir, sha256sum
from utils.logger import get_logger

log = get_logger(__name__)

FLAG_PATTERN_HINT = re.compile(r"flag\{[^}]+\}|ctf\{[^}]+\}", re.IGNORECASE)


def fetch_challenge_page(url: str) -> str:
    resp = requests.get(url, timeout=20)
    resp.raise_for_status()
    return resp.text


def parse_metadata(html: str, source_url: str) -> ChallengeMetadata:
    soup = BeautifulSoup(html, "html.parser")
    title_tag = soup.find("title")
    title = title_tag.text.strip() if title_tag else "challenge"
    description_el = soup.find("div", class_=re.compile("description|challenge"))
    description = description_el.get_text("\n", strip=True) if description_el else None
    flag_hint = None
    if description:
        match = FLAG_PATTERN_HINT.search(description)
        if match:
            flag_hint = match.group(0)
    category = None
    cat_el = soup.find(string=re.compile("category", re.IGNORECASE))
    if cat_el and cat_el.parent:
        category = cat_el.parent.get_text(strip=True)
    return ChallengeMetadata(
        source_url=source_url,
        title=title,
        category=category,
        description=description,
        flag_format=flag_hint,
        attachments=[],
    )


def download_attachments(urls: List[str], out_dir: Path) -> List[AttachmentRecord]:
    ensure_dir(out_dir)
    records: List[AttachmentRecord] = []
    for url in urls:
        name = url.split("/")[-1] or "attachment.bin"
        dest = out_dir / name
        try:
            with requests.get(url, stream=True, timeout=30) as r:
                r.raise_for_status()
                with dest.open("wb") as fh:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            fh.write(chunk)
            info = analyze_file(dest)
            records.append(
                AttachmentRecord(path=dest, sha256=info.get("sha256", sha256sum(dest)), mime=info.get("mime")),
            )
            log.info("Downloaded attachment: %s", dest)
        except Exception as exc:  # noqa: BLE001
            log.error("Failed to download %s: %s", url, exc)
    return records


def ingest_from_url(page_url: str, attachment_urls: Optional[List[str]], download_dir: Path) -> ChallengeMetadata:
    html = fetch_challenge_page(page_url)
    meta = parse_metadata(html, page_url)
    if attachment_urls:
        meta.attachments = [rec.path for rec in download_attachments(attachment_urls, download_dir)]
    return meta
