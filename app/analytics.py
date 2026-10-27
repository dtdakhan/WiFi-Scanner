"""Các trường suy ra từ dữ liệu thật của phiên quét (không đoán)."""
from __future__ import annotations

from collections import Counter

from .models import AccessPoint
from .vendor import VendorDB


def current_sample(ap: AccessPoint):
    if ap.signal_dbm is not None:
        return "dBm", ap.signal_dbm
    if ap.signal_percent is not None:
        return "%", ap.signal_percent
    return None, None


def annotate(aps: list[AccessPoint], prev: dict[str, tuple[str, float]], first_seen: dict[str, str],
             now: str, vendors: VendorDB) -> None:
    """prev: BSSID -> (đơn vị, giá trị) của lần đo trước. Delta chỉ tính khi cùng đơn vị."""
    crowd = Counter((a.band, a.channel) for a in aps if a.channel is not None and a.band != "Unknown")
    for a in aps:
        unit, val = current_sample(a)
        p = prev.get(a.bssid)
        a.signal_delta = round(val - p[1], 1) if val is not None and p and p[0] == unit else None
        a.channel_ap_count = crowd.get((a.band, a.channel)) if a.channel is not None else None
        first_seen.setdefault(a.bssid, now)
        a.first_seen, a.last_seen = first_seen[a.bssid], now
        a.vendor = vendors.lookup(a.bssid)
