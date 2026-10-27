"""Xuất dữ liệu chuẩn hóa (không phải chuỗi đã định dạng trong bảng). Không chứa mật khẩu/thông tin xác thực."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable

from .models import AccessPoint

PRIVACY_WARNING = "BSSID có thể được dùng để xác định vị trí địa lý. Cân nhắc trước khi chia sẻ file."
COLUMNS = ["ssid", "bssid", "signal_dbm", "signal_percent", "signal_raw", "channel", "frequency_mhz", "band",
           "channel_width", "security", "security_scope", "cipher", "radio_type", "is_connected", "is_hidden",
           "interface_name", "age_ms", "signal_delta", "channel_ap_count", "vendor", "first_seen", "last_seen", "source_os", "source_method", "scan_timestamp"]


class ExportError(Exception):
    pass


def export_json(aps: Iterable[AccessPoint], path: str, scope: str = "all") -> str:
    data = {"scope": scope, "privacy_note": PRIVACY_WARNING, "access_points": [a.to_dict() for a in aps]}
    try:
        Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError as e:
        raise ExportError(f"Không ghi được file '{path}': {e.strerror or e}") from e
    return str(path)


def export_csv(aps: Iterable[AccessPoint], path: str) -> str:
    try:
        with open(path, "w", newline="", encoding="utf-8-sig") as f:   # BOM để Excel đọc đúng tiếng Việt
            w = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore")
            w.writeheader()
            for a in aps:
                w.writerow({k: ("" if v is None else v) for k, v in a.to_dict().items()})
    except OSError as e:
        raise ExportError(f"Không ghi được file '{path}': {e.strerror or e}") from e
    return str(path)
