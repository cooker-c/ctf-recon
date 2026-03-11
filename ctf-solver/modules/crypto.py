from __future__ import annotations

import base64
import binascii
from typing import List

from core.analyzer import AnalysisModule
from utils.logger import get_logger

log = get_logger(__name__)


class CryptoModule(AnalysisModule):
    name = "crypto"
    description = "Lightweight crypto heuristics (base64/hex blobs)."

    def run(self, file_path: str, data: bytes) -> List[str]:
        outputs: List[str] = []
        outputs.extend(self._decode_hex_blocks(data))
        outputs.extend(self._decode_base64_blocks(data))
        return outputs

    def _decode_hex_blocks(self, data: bytes, min_len: int = 16) -> List[str]:
        decoded: List[str] = []
        current: bytearray = bytearray()
        for byte in data:
            if 48 <= byte <= 57 or 65 <= byte <= 70 or 97 <= byte <= 102:
                current.append(byte)
            else:
                decoded.extend(self._flush_hex(current, min_len))
                current.clear()
        decoded.extend(self._flush_hex(current, min_len))
        return decoded

    def _flush_hex(self, buf: bytearray, min_len: int) -> List[str]:
        if len(buf) < min_len:
            return []
        text = bytes(buf).decode()
        try:
            raw = binascii.unhexlify(text)
            return [raw.decode(errors="ignore")]
        except Exception:  # noqa: BLE001
            return []

    def _decode_base64_blocks(self, data: bytes, min_len: int = 24) -> List[str]:
        decoded: List[str] = []
        current: bytearray = bytearray()
        valid = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        for byte in data:
            if byte in valid:
                current.append(byte)
            else:
                decoded.extend(self._flush_b64(current, min_len))
                current.clear()
        decoded.extend(self._flush_b64(current, min_len))
        return decoded

    def _flush_b64(self, buf: bytearray, min_len: int) -> List[str]:
        if len(buf) < min_len:
            return []
        try:
            raw = base64.b64decode(bytes(buf), validate=True)
            return [raw.decode(errors="ignore")]
        except Exception:  # noqa: BLE001
            return []
