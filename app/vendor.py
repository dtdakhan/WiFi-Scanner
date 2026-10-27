"""Tra hãng sản xuất từ OUI (3 byte đầu của BSSID). Dữ liệu OUI lấy từ file IEEE do người dùng tải về;
không có file thì Vendor hiển thị N/A (không đoán). BSSID 'cục bộ' (bit locally-administered) không có hãng."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

LAA_LABEL = "MAC cục bộ (LAA)"
_LINE = re.compile(r"^\s*([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+?)\s*$")
DEFAULT_PATH = Path(__file__).parent / "data" / "oui.txt"


def is_locally_administered(bssid: str) -> bool:
    return bool(int(bssid[:2], 16) & 0x02)


def parse_oui(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = _LINE.match(line)
        if m:
            out["".join(m.group(1, 2, 3)).upper()] = m.group(4)
    return out


class VendorDB:
    def __init__(self, table: Optional[dict[str, str]] = None) -> None:
        self.table = table or {}

    @classmethod
    def load_default(cls) -> "VendorDB":
        path = Path(os.environ.get("WIFI_SCANNER_OUI", DEFAULT_PATH))
        try:
            return cls(parse_oui(path.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            return cls()

    def lookup(self, bssid: Optional[str]) -> Optional[str]:
        if not bssid or len(bssid) < 8:
            return None
        if is_locally_administered(bssid):
            return LAA_LABEL
        return self.table.get(bssid[:8].replace(":", "").upper())
