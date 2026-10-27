"""Giải thích thông số: mỗi thông số một hàng gồm Giải thích / Từ viết tắt nghĩa là gì (không có ví dụ).
Cửa sổ độc lập (không chặn cửa sổ chính) có nút thu nhỏ / phóng to / đóng; chữ thu phóng được bằng A−/A+ hoặc Ctrl + lăn chuột."""
from html import escape

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (QAbstractItemView, QDialog, QHBoxLayout, QHeaderView, QLabel, QPushButton,
                               QTableWidget, QTableWidgetItem, QVBoxLayout)

# (tên cột — trùng tiêu đề bảng chính, giải thích, từ viết tắt nghĩa là gì). Không có ví dụ.
TERMS = [
    ("SSID", "Tên của mạng Wi-Fi. Để trống nghĩa là mạng ẩn.",
     "SSID = Service Set Identifier (định danh tập dịch vụ)."),
    ("BSSID (MAC)", "Địa chỉ phần cứng của từng thiết bị phát sóng; mỗi thiết bị hoặc mỗi băng tần có một địa chỉ riêng. Mỗi dòng trong bảng ứng với một BSSID.",
     "BSSID = Basic Service Set Identifier. MAC = Media Access Control (điều khiển truy cập môi trường), địa chỉ phần cứng của card mạng."),
    ("Signal", "Cường độ tín hiệu máy bạn thu được từ thiết bị phát. Tính bằng dBm thì là số âm, càng gần 0 càng mạnh; tính bằng phần trăm thì càng cao càng mạnh. Chỉ phản ánh sóng thu được, không phải tốc độ Internet.",
     "dBm = decibel-milliwatt (đơn vị công suất). RSSI = Received Signal Strength Indicator (chỉ báo cường độ tín hiệu thu)."),
    ("Δ Signal", "Độ chênh lệch tín hiệu so với lần đo trước: ▲ là mạnh lên, ▼ là yếu đi. Chỉ có khi quét liên tục.",
     "Δ = Delta (độ chênh lệch)."),
    ("Channel", "Kênh mà thiết bị phát dùng để phát sóng trong một băng tần. Các thiết bị dùng cùng kênh hoặc kênh sát nhau dễ gây nhiễu cho nhau.",
     "Không có từ viết tắt."),
    ("Frequency", "Tần số trung tâm của kênh.",
     "MHz = megahertz (triệu dao động mỗi giây). GHz = gigahertz = 1000 MHz."),
    ("Band", "Băng tần: dải tần số mà thiết bị phát sử dụng (2.4 GHz, 5 GHz hoặc 6 GHz). Băng thấp đi xa hơn nhưng chậm và dễ nhiễu; băng cao nhanh hơn nhưng tầm ngắn hơn.",
     "GHz = gigahertz."),
    ("Security", "Kiểu bảo mật mà thiết bị phát báo cáo. Open là không mật khẩu; WPA2 và WPA3 là bảo mật hiện đại (WPA3 mới hơn); WEP và WPA đời đầu đã lỗi thời. Personal dùng một mật khẩu chung, Enterprise dùng tài khoản riêng cho từng người.",
     "WEP = Wired Equivalent Privacy. WPA = Wi-Fi Protected Access. PSK = Pre-Shared Key (khóa chia sẻ trước, tức mật khẩu chung). 802.1X = chuẩn xác thực bằng tài khoản."),
    ("Cipher", "Thuật toán mã hóa dữ liệu truyền qua sóng. CCMP và GCMP là hiện đại; TKIP là cũ và yếu.",
     "CCMP = Counter Mode with CBC-MAC Protocol. GCMP = Galois/Counter Mode Protocol. TKIP = Temporal Key Integrity Protocol. AES = Advanced Encryption Standard (chuẩn mã hóa nâng cao), thuật toán mà CCMP và GCMP sử dụng."),
    ("Radio Type", "Chuẩn Wi-Fi mà thiết bị phát hỗ trợ: 802.11n là Wi-Fi 4, 802.11ac là Wi-Fi 5, 802.11ax là Wi-Fi 6 (6E khi có băng 6 GHz), 802.11be là Wi-Fi 7.",
     "IEEE = Institute of Electrical and Electronics Engineers, tổ chức đặt ra họ chuẩn 802.11."),
    ("Connection", "Cho biết máy bạn có đang kết nối đúng thiết bị phát này không; so sánh theo BSSID chứ không theo SSID.",
     "AP = Access Point (điểm truy cập: router, bộ phát Wi-Fi)."),
    ("AP cùng kênh", "Số thiết bị phát dùng cùng băng tần và kênh, gồm cả chính nó; số càng lớn thì kênh càng đông, dễ nhiễu. Chỉ tính trong lần quét hiện tại.",
     "AP = Access Point."),
    ("Vendor", "Hãng sản xuất thiết bị phát, tra từ 3 byte đầu của BSSID; cần file dữ liệu OUI (xem README). 'MAC cục bộ (LAA)' là địa chỉ do phần mềm gán nên không tra được hãng.",
     "OUI = Organizationally Unique Identifier (định danh duy nhất của tổ chức). LAA = Locally Administered Address (địa chỉ do phần mềm gán)."),
    ("Thấy lần đầu", "Giờ lần đầu tiên thấy thiết bị này trong phiên quét hiện tại.", "Không có từ viết tắt."),
    ("Thấy lần cuối", "Giờ gần nhất còn thấy thiết bị này trong phiên quét hiện tại.", "Không có từ viết tắt."),
    ("N/A", "Ứng dụng không có dữ liệu cho ô này vì hệ điều hành không cung cấp; ứng dụng không tự đoán.",
     "N/A = Not Available (không có sẵn)."),
]

ZOOM_MIN, ZOOM_MAX, ZOOM_STEP, BASE_PT = 0.6, 2.5, 0.1, 10.0


def tooltip_for(header: str) -> str:
    return next((what for name, what, *_ in TERMS if name == header), "")


def glossary_html() -> str:
    rows = "".join(f"<tr><td><b>{escape(n)}</b></td><td>{escape(w)}</td><td>{escape(a)}</td></tr>"
                   for n, w, a in TERMS)
    return f"<table border='1' cellspacing='0' cellpadding='4'>{rows}</table>"


class ZoomTable(QTableWidget):
    def __init__(self, on_zoom) -> None:
        super().__init__()
        self._on_zoom = on_zoom

    def wheelEvent(self, e) -> None:                       # Ctrl + lăn chuột để thu phóng
        if e.modifiers() & Qt.ControlModifier:
            self._on_zoom(ZOOM_STEP if e.angleDelta().y() > 0 else -ZOOM_STEP)
            e.accept()
        else:
            super().wheelEvent(e)


class GlossaryDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        # cửa sổ độc lập, không modal: vừa xem giải thích vừa xem kết quả quét ở cửa sổ chính
        self.setWindowFlags(Qt.Window | Qt.WindowMinMaxButtonsHint | Qt.WindowCloseButtonHint)
        self.setModal(False)
        self.setWindowTitle("Giải thích thông số")
        self.resize(1000, 560)
        self.zoom = 1.0
        lay = QVBoxLayout(self)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Cỡ chữ:"))
        for text, delta in (("A−", -ZOOM_STEP), ("A+", ZOOM_STEP)):
            b = QPushButton(text); b.setFixedWidth(44); b.setToolTip("Chỉnh cỡ chữ")
            b.clicked.connect(lambda _=False, d=delta: self.change_zoom(d)); bar.addWidget(b)
        reset = QPushButton("100%"); reset.clicked.connect(lambda: self.set_zoom(1.0)); bar.addWidget(reset)
        self.lbl = QLabel(); bar.addWidget(self.lbl)
        bar.addStretch(); bar.addWidget(QLabel("Cỡ chữ: Ctrl + lăn chuột"))
        lay.addLayout(bar)

        self.table = ZoomTable(self.change_zoom)
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Thông số", "Giải thích", "Từ viết tắt nghĩa là"])
        self.table.setRowCount(len(TERMS))
        for r, row in enumerate(TERMS):
            for c, text in enumerate(row):
                it = QTableWidgetItem(text)
                if c == 0:
                    f = it.font(); f.setBold(True); it.setFont(f)
                it.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                self.table.setItem(r, c, it)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.Interactive)
        for c in (1, 2):
            hh.setSectionResizeMode(c, QHeaderView.Stretch)
        hh.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.table.verticalHeader().hide()
        self.table.setWordWrap(True); self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        lay.addWidget(self.table, 1)

        for seq, d in (("Ctrl++", ZOOM_STEP), ("Ctrl+=", ZOOM_STEP), ("Ctrl+-", -ZOOM_STEP)):
            QShortcut(QKeySequence(seq), self, activated=lambda d=d: self.change_zoom(d))
        QShortcut(QKeySequence("Ctrl+0"), self, activated=lambda: self.set_zoom(1.0))
        self.set_zoom(1.0)

    def change_zoom(self, delta: float) -> None:
        self.set_zoom(self.zoom + delta)

    def set_zoom(self, value: float) -> None:
        self.zoom = round(min(ZOOM_MAX, max(ZOOM_MIN, value)), 2)
        f = self.table.font(); f.setPointSizeF(BASE_PT * self.zoom)
        self.table.setFont(f); self.table.horizontalHeader().setFont(f)
        self.table.setColumnWidth(0, int(130 * self.zoom))
        self.table.resizeRowsToContents()
        self.lbl.setText(f"{round(self.zoom * 100)}%")

    def showEvent(self, e) -> None:
        super().showEvent(e)
        QTimer.singleShot(0, self.table.resizeRowsToContents)   # đo lại sau khi cột đã có độ rộng cuối

    def resizeEvent(self, e) -> None:
        super().resizeEvent(e)
        self.table.resizeRowsToContents()                  # chữ xuống dòng lại khi đổi kích thước cửa sổ