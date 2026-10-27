"""Bảng thống kê dạng thẻ: mỗi chỉ số một ô riêng, số lớn + nhãn nhỏ."""
from __future__ import annotations

from PySide6.QtWidgets import QFrame, QGridLayout, QHBoxLayout, QLabel, QVBoxLayout, QWidget

# (khóa, nhãn ngắn, tooltip đầy đủ)
CARDS = [("total", "Tổng AP", "Tổng số Access Point tìm thấy"), ("ssid", "SSID", "Số SSID duy nhất"),
         ("bssid", "BSSID", "Số BSSID duy nhất"), ("sec_known", "Có bảo mật", "Số AP có thông tin bảo mật"),
         ("sec_none", "Không có dữ liệu", "Số AP nguồn dữ liệu không cung cấp thông tin bảo mật"),
         ("time", "Quét gần nhất", "Thời điểm quét gần nhất")]


class StatCard(QFrame):
    """Chip nhỏ gọn: nhãn đứng trước, số đứng sau."""

    def __init__(self, caption: str, tip: str) -> None:
        super().__init__()
        self.setObjectName("card"); self.setToolTip(tip)
        lay = QHBoxLayout(self); lay.setContentsMargins(10, 4, 10, 4); lay.setSpacing(6)
        cap = QLabel(caption); cap.setObjectName("cardCaption")
        self.value = QLabel("—"); self.value.setObjectName("cardValue")
        lay.addWidget(cap); lay.addWidget(self.value)

    def set_value(self, text: str) -> None:
        self.value.setText(text)


class StatsPanel(QWidget):
    def __init__(self) -> None:
        super().__init__()
        outer = QVBoxLayout(self); outer.setContentsMargins(0, 0, 0, 0); outer.setSpacing(6)
        row = QHBoxLayout(); row.setSpacing(8)
        self.cards = {key: StatCard(cap, tip) for key, cap, tip in CARDS}
        for c in self.cards.values():
            row.addWidget(c)
        row.addStretch(1)
        outer.addLayout(row)
        self.lbl_info = QLabel(""); self.lbl_info.setObjectName("muted"); self.lbl_info.setWordWrap(True)
        outer.addWidget(self.lbl_info)

    def clear(self) -> None:
        for c in self.cards.values():
            c.set_value("—")
        self.lbl_info.setText("")

    def update_from(self, aps, result, scan_no: int, live: bool) -> None:
        known = sum(1 for a in aps if a.security is not None)
        t = (result.timestamp or "")
        clock = t[11:19] if len(t) >= 19 else "N/A"
        vals = {"total": len(aps), "ssid": len({a.ssid for a in aps if a.ssid}),
                "bssid": len({a.bssid for a in aps}), "sec_known": known, "sec_none": len(aps) - known,
                "time": clock}
        for k, v in vals.items():
            self.cards[k].set_value(str(v))
        bands = {b: sum(1 for a in aps if a.band == b) for b in ("2.4 GHz", "5 GHz", "6 GHz", "Unknown")}
        band_txt = "  ".join(f"{b}: {n}" for b, n in bands.items() if n or b != "Unknown")
        mode = "liên tục" if live else "một lần"
        self.lbl_info.setText(f"Băng tần — {band_txt}   |   Nguồn: {result.method}   |   "
                              f"Lần đo #{scan_no} ({mode}), {result.elapsed_s:.1f}s")
