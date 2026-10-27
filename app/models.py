"""Cấu trúc dữ liệu thống nhất. Trường không có dữ liệu = None (hiển thị N/A)."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional


@dataclass
class AccessPoint:
    ssid: Optional[str] = None              # "" = mạng ẩn; None = nguồn không cung cấp
    bssid: Optional[str] = None
    signal_dbm: Optional[float] = None
    signal_percent: Optional[int] = None
    signal_raw: Optional[str] = None
    channel: Optional[int] = None
    frequency_mhz: Optional[int] = None
    band: str = "Unknown"                   # 2.4 GHz | 5 GHz | 6 GHz | Unknown
    channel_width: Optional[str] = None
    security: Optional[str] = None          # đúng như nguồn báo cáo
    security_scope: Optional[str] = None    # "per_bssid" | "per_ssid"
    cipher: Optional[str] = None
    radio_type: Optional[str] = None
    is_connected: Optional[bool] = None     # so sánh theo BSSID
    is_hidden: Optional[bool] = None
    interface_name: Optional[str] = None
    age_ms: Optional[int] = None            # tuổi bản ghi (nếu nguồn cho biết)
    # --- trường suy ra trong phiên (xem analytics.py) ---
    signal_delta: Optional[float] = None    # chênh lệch so với lần đo trước, cùng đơn vị
    channel_ap_count: Optional[int] = None  # số AP cùng band+channel trong lần quét này (gồm chính nó)
    vendor: Optional[str] = None            # từ OUI nếu có dữ liệu
    first_seen: Optional[str] = None        # HH:MM:SS trong phiên
    last_seen: Optional[str] = None
    source_os: str = ""
    source_method: str = ""
    scan_timestamp: Optional[str] = None    # ISO 8601
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, include_raw: bool = False) -> dict[str, Any]:
        d = asdict(self)
        if not include_raw:
            d.pop("raw", None)
        return d


@dataclass
class WifiInterface:
    name: str
    description: str = ""
    state: Optional[str] = None


@dataclass
class ScanResult:
    aps: list[AccessPoint] = field(default_factory=list)
    method: str = ""
    source_os: str = ""
    interface: Optional[str] = None
    interfaces: list[WifiInterface] = field(default_factory=list)
    adapter_state: Optional[str] = None
    timestamp: str = ""
    elapsed_s: float = 0.0
    source_count: int = 0                   # bản ghi nguồn trả về
    dropped: list[str] = field(default_factory=list)   # lý do từng bản ghi bị loại
    warnings: list[str] = field(default_factory=list)
    stderr: str = ""

    @property
    def parsed_count(self) -> int:
        return len(self.aps)
