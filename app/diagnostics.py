"""Chẩn đoán: xác định lỗi thuộc bước quét, lấy dữ liệu, parsing, lọc hay hiển thị."""
from __future__ import annotations

import getpass
import os
import platform
import sys
from typing import Optional

from .models import ScanResult
from .scanner_base import ScanError

EMPTY_HINTS = {
    "Windows": "Kiểm tra: Wi-Fi bật, dịch vụ WLAN AutoConfig chạy, Location bật (Windows 11), driver cập nhật.",
    "Linux": "Kiểm tra: NetworkManager chạy, `nmcli radio wifi` = enabled, rfkill không chặn, đứng trong vùng phủ sóng.",
    "macOS": "Kiểm tra: Wi-Fi bật và ứng dụng được cấp Location Services (SSID/BSSID bị che nếu thiếu).",
}


def sanitize(text: str) -> str:
    for secret, repl in ((os.path.expanduser("~"), "~"), (_user(), "<user>")):
        if secret and len(secret) > 2:
            text = text.replace(secret, repl)
    return text


def _user() -> str:
    try:
        return getpass.getuser()
    except (KeyError, OSError):
        return ""


def system_info() -> dict[str, str]:
    return {"OS": f"{platform.system()} {platform.release()} ({platform.version()})", "Machine": platform.machine(),
            "Python": sys.version.split()[0]}


def classify(result: Optional[ScanResult], error: Optional[ScanError]) -> str:
    if error is not None:
        return f"SCAN KHÔNG THÀNH CÔNG ({error.kind})"
    if result is None:
        return "Chưa quét"
    if result.source_count == 0:
        return "Scan chạy xong nhưng nguồn trả về 0 bản ghi (không phải lỗi parser)"
    if result.parsed_count == 0:
        return "Nguồn có dữ liệu nhưng parser không xử lý được bản ghi nào (lỗi PARSING)"
    return "Scan thành công"


def format_report(result: Optional[ScanResult], error: Optional[ScanError] = None,
                  shown: Optional[int] = None) -> str:
    L = ["=== Hệ thống ==="] + [f"{k}: {v}" for k, v in system_info().items()]
    L += ["", "=== Kết luận ===", classify(result, error)]
    if error:
        L += [f"Lỗi: {error.message}", f"Cách khắc phục: {error.hint or 'N/A'}"]
        if error.stderr:
            L.append("stderr: " + sanitize(error.stderr))
    if result:
        L += ["", "=== Scan ===", f"Phương thức: {result.method}", f"Interface: {result.interface or 'tự động'}",
              f"Adapter: {result.adapter_state or 'N/A'}",
              "Interfaces: " + (", ".join(f"{i.name} [{i.state or 'N/A'}]" for i in result.interfaces) or "N/A"),
              f"Thời gian scan: {result.elapsed_s:.2f}s", f"Bản ghi nguồn: {result.source_count}",
              f"Bản ghi parse được: {result.parsed_count}", f"Bản ghi bị loại: {len(result.dropped)}"]
        L += [f"  - {sanitize(d)}" for d in result.dropped[:50]]
        if shown is not None:
            L.append(f"Hiển thị sau lọc: {shown}")
        L += [f"Cảnh báo: {w}" for w in result.warnings]
        if result.source_count == 0 and not error:
            L.append("Gợi ý: " + EMPTY_HINTS.get(result.source_os, ""))
    return "\n".join(L)
