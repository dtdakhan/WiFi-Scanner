from __future__ import annotations

from typing import Optional

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor

from ..models import AccessPoint
from ..normalizer import sort_aps
from ..signal_utils import NA, format_signal, signal_level
from .glossary import tooltip_for
from .styles import LEVEL_COLORS

COLUMNS = [("SSID", "ssid"), ("BSSID (MAC)", "bssid"), ("Signal", "signal"), ("Δ Signal", "signal_delta"),
           ("Channel", "channel"), ("Frequency", "frequency_mhz"), ("Band", "band"), ("Security", "security"),
           ("Cipher", "cipher"), ("Radio Type", "radio_type"), ("Connection", "is_connected"),
           ("AP cùng kênh", "channel_ap_count"), ("Vendor", "vendor"),
           ("Thấy lần đầu", "first_seen"), ("Thấy lần cuối", "last_seen")]
DEFAULT_HIDDEN = ("vendor", "first_seen", "last_seen")
DEFAULT_WIDTHS = (220, 150, 90, 90, 70, 100, 80, 150, 90, 100, 100, 110, 160, 110, 110)


def format_delta(ap: AccessPoint) -> str:
    d = ap.signal_delta
    if d is None:
        return NA
    unit = "dBm" if ap.signal_dbm is not None else "%"
    return f"▲ +{d:g} {unit}" if d > 0 else f"▼ {d:g} {unit}" if d < 0 else f"= 0 {unit}"


def cell_text(ap: AccessPoint, col: int) -> str:
    key = COLUMNS[col][1]
    if key == "ssid":
        return "(mạng ẩn)" if ap.ssid == "" else (ap.ssid if ap.ssid is not None else NA)
    if key == "signal":
        return format_signal(ap)
    if key == "signal_delta":
        return format_delta(ap)
    if key == "frequency_mhz":
        return f"{ap.frequency_mhz} MHz" if ap.frequency_mhz is not None else NA
    if key == "is_connected":
        return NA if ap.is_connected is None else ("Đã kết nối" if ap.is_connected else "Không")
    v = getattr(ap, key)
    return NA if v in (None, "", "Unknown") else str(v)


class NetworkModel(QAbstractTableModel):
    def __init__(self) -> None:
        super().__init__()
        self._rows: list[AccessPoint] = []
        self._sort = ("signal", True)

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return COLUMNS[section][0]
        if orientation == Qt.Horizontal and role == Qt.ToolTipRole:
            return tooltip_for(COLUMNS[section][0])
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        ap = self._rows[index.row()]
        if role == Qt.DisplayRole:
            return cell_text(ap, index.column())
        if role == Qt.ForegroundRole and COLUMNS[index.column()][1] == "signal_delta":
            d = ap.signal_delta
            return QColor("#15803d" if d and d > 0 else "#b91c1c") if d else None
        if role == Qt.ForegroundRole and COLUMNS[index.column()][1] == "signal":
            lvl = signal_level(ap)
            return QColor(LEVEL_COLORS[lvl]) if lvl else None
        if role == Qt.ToolTipRole and COLUMNS[index.column()][1] == "signal":
            return "Tín hiệu mạnh hơn = RSSI gần 0 dBm hơn (vd -50 mạnh hơn -80). Không phản ánh tốc độ Internet."
        return None

    def set_rows(self, aps: list[AccessPoint]) -> None:
        self.beginResetModel()
        self._rows = sort_aps(aps, *self._sort)
        self.endResetModel()

    def sort(self, column: int, order=Qt.AscendingOrder) -> None:
        self._sort = (COLUMNS[column][1], order == Qt.DescendingOrder)
        self.set_rows(list(self._rows))

    def ap_at(self, row: int) -> Optional[AccessPoint]:
        return self._rows[row] if 0 <= row < len(self._rows) else None

    def rows(self) -> list[AccessPoint]:
        return list(self._rows)
