from __future__ import annotations

from typing import Optional

from PySide6.QtWidgets import QPlainTextEdit

from ..models import AccessPoint
from ..signal_utils import NA, format_signal
from .network_table import format_delta


def history_lines(hist) -> list[str]:
    """hist: [(giờ, đơn vị, giá trị)] theo thời gian. Chỉ thống kê trong cùng một đơn vị."""
    if not hist:
        return []
    unit = hist[-1][1]
    vals = [v for _, u, v in hist if u == unit]
    fmt = (lambda x: f"{x:g} dBm") if unit == "dBm" else (lambda x: f"{x:g}%")
    recent = " → ".join(fmt(v) for _, u, v in hist[-10:] if u == unit)
    return [("Số lần đo", str(len(hist))), ("Min / Max / TB", f"{fmt(min(vals))} / {fmt(max(vals))} / {fmt(sum(vals) / len(vals))}"),
            ("Gần đây (cũ → mới)", recent)]


def describe(ap: Optional[AccessPoint], history=None) -> str:
    if ap is None:
        return "Chọn một Access Point trong bảng để xem chi tiết."
    def v(x): return NA if x in (None, "") else str(x)
    rows = [("SSID", "(mạng ẩn)" if ap.ssid == "" else v(ap.ssid)), ("BSSID", v(ap.bssid)),
            ("Signal", format_signal(ap)),
            ("Signal (dBm)", v(ap.signal_dbm)), ("Signal (%)", v(ap.signal_percent)), ("Signal (nguyên bản)", v(ap.signal_raw)),
            ("Frequency", f"{ap.frequency_mhz} MHz" if ap.frequency_mhz else NA), ("Channel", v(ap.channel)),
            ("Band", v(None if ap.band == "Unknown" else ap.band)), ("Channel width", v(ap.channel_width)),
            ("Security", v(ap.security)), ("Security scope", v(ap.security_scope)), ("Cipher", v(ap.cipher)),
            ("Radio type", v(ap.radio_type)),
            ("Kết nối", NA if ap.is_connected is None else ("Đã kết nối (theo BSSID)" if ap.is_connected else "Không")),
            ("Δ so với lần đo trước", format_delta(ap)), ("AP cùng kênh", v(ap.channel_ap_count)),
            ("Vendor", v(ap.vendor)), ("Thấy lần đầu / cuối", f"{v(ap.first_seen)} / {v(ap.last_seen)}"),
            ("Interface", v(ap.interface_name)), ("Tuổi bản ghi (ms)", v(ap.age_ms)),
            ("Thời điểm thu thập", v(ap.scan_timestamp)), ("Nguồn", f"{v(ap.source_os)} / {v(ap.source_method)}")]
    rows += history_lines(history)
    return "\n".join(f"{k:<22}{val}" for k, val in rows)


class NetworkDetails(QPlainTextEdit):
    def __init__(self) -> None:
        super().__init__()
        self.setReadOnly(True)
        self.setPlainText(describe(None))
        self.setStyleSheet("font-family: Consolas, 'DejaVu Sans Mono', monospace;")

    def show_ap(self, ap: Optional[AccessPoint], history=None) -> None:
        sb = self.verticalScrollBar().value()
        self.setPlainText(describe(ap, history))
        self.verticalScrollBar().setValue(sb)
