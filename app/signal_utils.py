"""Tín hiệu và tần số. Band được xác định TRƯỚC từ dải tần, rồi mới tính channel
(vì số kênh 6 GHz trùng số kênh 5 GHz)."""
from __future__ import annotations

from typing import Optional

from .models import AccessPoint

NA = "N/A"


def band_from_frequency(freq_mhz: Optional[int]) -> Optional[str]:
    if freq_mhz is None:
        return None
    if 2400 <= freq_mhz <= 2500:
        return "2.4 GHz"
    if 5150 <= freq_mhz <= 5895:
        return "5 GHz"
    if 5925 <= freq_mhz <= 7125:
        return "6 GHz"
    return None


def channel_from_frequency(freq_mhz: Optional[int], band: Optional[str]) -> Optional[int]:
    """Chỉ trả về channel khi tần số khớp đúng lưới kênh của band; ngược lại None."""
    if freq_mhz is None or band is None:
        return None
    if band == "2.4 GHz":
        if freq_mhz == 2484:
            return 14
        if 2412 <= freq_mhz <= 2472 and (freq_mhz - 2407) % 5 == 0:
            return (freq_mhz - 2407) // 5
    elif band == "5 GHz":
        if 5170 <= freq_mhz <= 5895 and (freq_mhz - 5000) % 5 == 0:
            return (freq_mhz - 5000) // 5
    elif band == "6 GHz":
        if freq_mhz == 5935:
            return 2
        if 5955 <= freq_mhz <= 7115 and (freq_mhz - 5950) % 5 == 0:
            return (freq_mhz - 5950) // 5
    return None


def format_signal(ap: AccessPoint) -> str:
    if ap.signal_dbm is not None:
        return f"{ap.signal_dbm:g} dBm"
    if ap.signal_percent is not None:
        return f"{ap.signal_percent}%"
    return NA


def signal_level(ap: AccessPoint) -> Optional[str]:
    """strong/medium/weak CHỈ phản ánh tín hiệu thu được, không phải chất lượng Internet."""
    if ap.signal_dbm is not None:
        return "strong" if ap.signal_dbm >= -60 else "medium" if ap.signal_dbm >= -75 else "weak"
    if ap.signal_percent is not None:
        return "strong" if ap.signal_percent >= 66 else "medium" if ap.signal_percent >= 33 else "weak"
    return None


def sort_by_signal(aps: list[AccessPoint], descending: bool = True) -> list[AccessPoint]:
    """Không bao giờ so dBm với %. Nhóm dBm trước, nhóm % sau, không có tín hiệu cuối cùng.
    Trong từng nhóm, so cùng đơn vị."""
    dbm = [a for a in aps if a.signal_dbm is not None]
    pct = [a for a in aps if a.signal_dbm is None and a.signal_percent is not None]
    none = [a for a in aps if a.signal_dbm is None and a.signal_percent is None]
    dbm.sort(key=lambda a: a.signal_dbm, reverse=descending)
    pct.sort(key=lambda a: a.signal_percent, reverse=descending)
    return dbm + pct + none
