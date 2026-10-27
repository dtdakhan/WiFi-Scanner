"""Chuẩn hóa, sắp xếp, tìm kiếm, lọc. Không sửa dữ liệu gốc (luôn trả list mới)."""
from __future__ import annotations

import re
from typing import Any, Optional

from .models import AccessPoint
from .signal_utils import band_from_frequency, channel_from_frequency, sort_by_signal

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


def normalize_mac(value: Optional[str]) -> str:
    if value is None or not _MAC_RE.match(value.strip()):
        raise ValueError(f"BSSID không hợp lệ: {value!r}")
    return value.strip().replace("-", ":").upper()


def finalize_ap(ap: AccessPoint) -> AccessPoint:
    """Điền band/channel chỉ khi suy ra hợp lệ từ frequency; không đoán security/radio."""
    ap.bssid = normalize_mac(ap.bssid)
    if ap.ssid is not None:
        ap.ssid = ap.ssid.replace("\x00", "")
        ap.is_hidden = ap.ssid == ""
    if ap.signal_percent is not None and not 0 <= ap.signal_percent <= 100:
        raise ValueError(f"Phần trăm tín hiệu ngoài phạm vi: {ap.signal_percent}")
    if ap.band in (None, "", "Unknown"):
        ap.band = band_from_frequency(ap.frequency_mhz) or "Unknown"
    if ap.channel is None:
        ap.channel = channel_from_frequency(ap.frequency_mhz, ap.band if ap.band != "Unknown" else None)
    return ap


def mark_connected(aps: list[AccessPoint], connected_bssid: Optional[str], known: bool) -> None:
    """So sánh theo BSSID (không theo SSID). known=False -> để None (không xác định)."""
    if not known:
        return
    target = None
    if connected_bssid:
        try:
            target = normalize_mac(connected_bssid)
        except ValueError:
            target = None
    for ap in aps:
        ap.is_connected = (ap.bssid == target) if target else False


def security_category(ap: AccessPoint) -> str:
    if ap.security is None:
        return "unknown"
    return "open" if ap.security.lower().startswith("open") else "secured"


def filter_aps(aps: list[AccessPoint], text: str = "", band: Optional[str] = None,
               security: Optional[str] = None, show_hidden: bool = True) -> list[AccessPoint]:
    q = text.strip().casefold()
    out = []
    for ap in aps:
        if q and q not in (ap.ssid or "").casefold() and q not in (ap.bssid or "").casefold():
            continue
        if band and ap.band != band:
            continue
        if security and security_category(ap) != security:
            continue
        if not show_hidden and ap.is_hidden:
            continue
        out.append(ap)
    return out


def _key_value(ap: AccessPoint, key: str) -> Any:
    v = getattr(ap, key)
    if key == "ssid":
        return None if not v else v.casefold()
    if key == "band":
        return None if v == "Unknown" else v
    if isinstance(v, str):
        return v.casefold()
    return v


def sort_aps(aps: list[AccessPoint], key: str = "signal", descending: bool = True) -> list[AccessPoint]:
    if key == "signal":
        return sort_by_signal(aps, descending)
    with_val = [a for a in aps if _key_value(a, key) is not None]
    without = [a for a in aps if _key_value(a, key) is None]
    with_val.sort(key=lambda a: _key_value(a, key), reverse=descending)
    return with_val + without   # giá trị thiếu luôn ở cuối
