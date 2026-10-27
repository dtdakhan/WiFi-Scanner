from __future__ import annotations

import logging
import platform
from collections import defaultdict
from datetime import datetime
from typing import Optional

from PySide6.QtCore import Qt, QThread, QTimer
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit,
                               QHeaderView, QMainWindow, QMenu, QMessageBox, QProgressBar, QPushButton, QSpinBox, QSplitter, QTableView,
                               QVBoxLayout, QWidget)

from .. import analytics, diagnostics, exporter
from ..vendor import VendorDB
from ..models import AccessPoint, ScanResult
from ..normalizer import filter_aps
from ..scanner_base import BaseScanner, ScanError
from ..workers import ScanWorker
from .diagnostics_panel import DiagnosticsDialog
from .glossary import GlossaryDialog
from .network_details import NetworkDetails
from .network_table import COLUMNS, DEFAULT_HIDDEN, DEFAULT_WIDTHS, NetworkModel
from .stats_panel import StatsPanel
from .styles import STYLE

log = logging.getLogger(__name__)
SEC_FILTERS = [("Tất cả security", None), ("Open", "open"), ("Có bảo mật", "secured"), ("Không có dữ liệu", "unknown")]


class MainWindow(QMainWindow):
    def __init__(self, scanner: BaseScanner, scan_timeout: float = 20.0) -> None:
        super().__init__()
        self.scanner, self.scan_timeout = scanner, scan_timeout
        self.all_aps: list[AccessPoint] = []
        self.last_result: Optional[ScanResult] = None
        self.last_error: Optional[ScanError] = None
        self._thread: Optional[QThread] = None
        self._worker: Optional[ScanWorker] = None
        self._live = False
        self._live_failures = 0
        self._scan_no = 0
        self.vendors = VendorDB.load_default()
        self._glossary: Optional[GlossaryDialog] = None
        self.first_seen: dict[str, str] = {}
        self.history: dict[str, list] = defaultdict(list)   # BSSID -> [(giờ, đơn vị, giá trị)]
        self.setWindowTitle("Wi-Fi Scanner")
        self.resize(1100, 700)
        self.setStyleSheet(STYLE)
        self._build()

    # ---- UI ----
    def _build(self) -> None:
        root = QWidget(); lay = QVBoxLayout(root); self.setCentralWidget(root)
        head = QHBoxLayout()
        t = QLabel("Wi-Fi Scanner"); t.setObjectName("title")
        self.lbl_os = QLabel(f"OS: {platform.system()} {platform.release()}")
        self.lbl_adapter = QLabel("Adapter: N/A")
        self.lbl_state = QLabel("Trạng thái: Chưa quét")
        for w in (t,): head.addWidget(w)
        head.addStretch()
        for w in (self.lbl_os, self.lbl_adapter, self.lbl_state):
            w.setObjectName("muted"); head.addWidget(w)
        lay.addLayout(head)

        tb = QHBoxLayout()
        self.btn_scan = QPushButton("▶ Quét"); self.btn_scan.setObjectName("primary")
        self.btn_scan.setToolTip("Bắt đầu quét liên tục (cập nhật theo thời gian thực). Bấm lại để dừng.")
        self.btn_scan.clicked.connect(self.toggle_live)
        self.cmb_iface = QComboBox(); self.cmb_iface.addItem("Interface: tự động", None)
        self.spin_interval = QSpinBox(); self.spin_interval.setRange(1, 60); self.spin_interval.setValue(3)
        self.spin_interval.setPrefix("mỗi "); self.spin_interval.setSuffix(" giây")
        self.btn_json = QPushButton("Xuất JSON"); self.btn_json.clicked.connect(lambda: self.export("json"))
        self.btn_csv = QPushButton("Xuất CSV"); self.btn_csv.clicked.connect(lambda: self.export("csv"))
        self.btn_diag = QPushButton("Chẩn đoán"); self.btn_diag.clicked.connect(self.show_diagnostics)
        self.btn_help = QPushButton("Giải thích thông số"); self.btn_help.clicked.connect(self.show_glossary)
        self.spinner = QProgressBar(); self.spinner.setRange(0, 0); self.spinner.setMaximumWidth(120)
        self.spinner.setTextVisible(False); self.spinner.hide()
        for w in (self.btn_scan, self.spin_interval, self.cmb_iface, self.btn_json, self.btn_csv, self.btn_diag, self.btn_help):
            tb.addWidget(w)
        tb.addWidget(self.spinner); tb.addStretch()
        lay.addLayout(tb)

        self.banner = QLabel(""); self.banner.setObjectName("banner"); self.banner.setWordWrap(True); self.banner.hide()
        lay.addWidget(self.banner)
        self.stats = StatsPanel(); lay.addWidget(self.stats)

        fl = QHBoxLayout()
        self.search = QLineEdit(); self.search.setPlaceholderText("Tìm theo SSID / BSSID"); self.search.setClearButtonEnabled(True)
        self.cmb_band = QComboBox(); self.cmb_band.addItems(["Tất cả băng tần", "2.4 GHz", "5 GHz", "6 GHz", "Unknown"])
        self.cmb_sec = QComboBox()
        for label, val in SEC_FILTERS:
            self.cmb_sec.addItem(label, val)
        self.chk_hidden = QCheckBox("Hiện mạng ẩn"); self.chk_hidden.setChecked(True)
        btn_clear = QPushButton("Xóa bộ lọc"); btn_clear.clicked.connect(self.clear_filters)
        for w in (self.search, self.cmb_band, self.cmb_sec, self.chk_hidden, btn_clear):
            fl.addWidget(w)
        lay.addLayout(fl)
        self.search.textChanged.connect(self.apply_filters)
        self.cmb_band.currentIndexChanged.connect(self.apply_filters)
        self.cmb_sec.currentIndexChanged.connect(self.apply_filters)
        self.chk_hidden.toggled.connect(self.apply_filters)

        self.model = NetworkModel()
        self.table = QTableView(); self.table.setModel(self.model)
        self.table.setSortingEnabled(True); self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows); self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.Interactive)      # kéo cạnh tiêu đề để đổi độ rộng cột
        hh.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)  # tên cột căn trái
        hh.setSectionsMovable(True)                           # kéo thả tiêu đề để đổi thứ tự cột
        hh.setStretchLastSection(True); hh.setMinimumSectionSize(50)
        for i, w in enumerate(DEFAULT_WIDTHS):
            self.table.setColumnWidth(i, w)
        for i, (_, key) in enumerate(COLUMNS):
            self.table.setColumnHidden(i, key in DEFAULT_HIDDEN)
        hh.setContextMenuPolicy(Qt.CustomContextMenu)         # chuột phải tiêu đề: bật/tắt cột
        hh.customContextMenuRequested.connect(self._column_menu)
        self.table.verticalHeader().hide()
        self.table.sortByColumn(2, Qt.DescendingOrder)
        self.table.selectionModel().selectionChanged.connect(self._on_select)
        self.details = NetworkDetails()
        split = QSplitter(Qt.Vertical); split.addWidget(self.table); split.addWidget(self.details)
        split.setStretchFactor(0, 3); split.setStretchFactor(1, 1)
        lay.addWidget(split, 1)
        self.lbl_count = QLabel("Hiển thị 0 / 0 AP"); lay.addWidget(self.lbl_count)
        hint = QLabel("Ứng dụng chỉ scan thụ động. Signal: RSSI gần 0 dBm hơn = mạnh hơn; màu chỉ phản ánh tín hiệu thu được.")
        hint.setObjectName("muted"); lay.addWidget(hint)

    # ---- Scan ----
    def start_scan(self) -> None:
        if self._thread is not None:          # chặn scan đồng thời
            return
        self._set_busy(True)
        if not self._live:
            self._show_banner("")
        self._thread = QThread()
        self._worker = ScanWorker(self.scanner, self.cmb_iface.currentData(), self.scan_timeout)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(lambda m: self.lbl_state.setText(f"Trạng thái: {m}"))
        self._worker.succeeded.connect(self._on_success)
        self._worker.failed.connect(self._on_failure)
        for sig in (self._worker.succeeded, self._worker.failed):
            sig.connect(self._thread.quit)
        self._thread.finished.connect(self._cleanup)
        self._thread.start()

    def _cleanup(self) -> None:
        if self._worker: self._worker.deleteLater()
        if self._thread: self._thread.deleteLater()
        self._worker = self._thread = None
        self._set_busy(False)                 # luôn dừng spinner dù thành công hay thất bại
        if self._live:                        # lần quét kế tiếp chỉ được hẹn SAU khi lần trước xong (không chồng lấn)
            QTimer.singleShot(self._interval_ms(), self._tick)

    def _interval_ms(self) -> int:
        return self.spin_interval.value() * 1000

    def _tick(self) -> None:
        if self._live and self._thread is None:
            self.start_scan()

    def toggle_live(self) -> None:
        """Nút Quét: bấm để bắt đầu quét liên tục, bấm lại để dừng."""
        self._live = not self._live
        self._live_failures = 0
        self._refresh_scan_button()
        if self._live:
            self.start_scan()
        else:
            self.lbl_state.setText("Trạng thái: Đã dừng")

    def _refresh_scan_button(self, busy: Optional[bool] = None) -> None:
        busy = self._thread is not None if busy is None else busy
        if self._live:
            self.btn_scan.setText("■ Dừng"); self.btn_scan.setEnabled(True)
        else:
            self.btn_scan.setText("Đang dừng..." if busy else "▶ Quét"); self.btn_scan.setEnabled(not busy)

    def _set_busy(self, busy: bool) -> None:
        self.spinner.setVisible(busy)
        self._refresh_scan_button(busy)
        self.cmb_iface.setEnabled(not busy)
        if busy: self.lbl_state.setText("Trạng thái: " + ("Đang đo (liên tục)" if self._live else "Đang quét"))

    def _on_success(self, result: ScanResult) -> None:
        self.last_result, self.last_error, self.all_aps = result, None, result.aps
        self._live_failures = 0
        self._scan_no += 1
        now = datetime.now().strftime("%H:%M:%S")
        prev = {b: (h[-1][1], h[-1][2]) for b, h in self.history.items() if h}
        analytics.annotate(result.aps, prev, self.first_seen, now, self.vendors)
        for a in result.aps:                              # ghi lịch sử theo từng BSSID
            if a.signal_dbm is not None:
                h = self.history[a.bssid]; h.append((now, "dBm", a.signal_dbm)); del h[:-120]
            elif a.signal_percent is not None:
                h = self.history[a.bssid]; h.append((now, "%", a.signal_percent)); del h[:-120]
        cur = self.cmb_iface.currentData()
        self.cmb_iface.blockSignals(True); self.cmb_iface.clear(); self.cmb_iface.addItem("Interface: tự động", None)
        for i in result.interfaces:
            self.cmb_iface.addItem(i.name, i.name)
        idx = self.cmb_iface.findData(cur); self.cmb_iface.setCurrentIndex(max(idx, 0)); self.cmb_iface.blockSignals(False)
        self.lbl_adapter.setText(f"Adapter: {result.adapter_state or 'N/A'}")
        self.lbl_state.setText(f"Trạng thái: {'Trực tiếp' if self._live else 'Hoàn tất'} · lần đo #{self._scan_no} lúc {now}")
        self.apply_filters()
        self._update_stats()
        msgs = list(result.warnings)
        level = "warn" if msgs else "ok"
        if result.source_count == 0:
            msgs.append("Scan thành công nhưng không tìm thấy AP nào. " + diagnostics.EMPTY_HINTS.get(result.source_os, ""))
            level = "warn"
        elif result.parsed_count == 0:
            msgs.append("Nguồn có dữ liệu nhưng không phân tích được bản ghi nào. Mở Chẩn đoán.")
            level = "error"
        if result.dropped:
            msgs.append(f"{len(result.dropped)} bản ghi bị loại (xem Chẩn đoán).")
        self._show_banner(" ".join(msgs), level)

    def _on_failure(self, err: ScanError) -> None:
        self.last_error = err
        self.lbl_state.setText("Trạng thái: Lỗi")
        if self._live:
            self._live_failures += 1
            if self._live_failures >= 3:                  # lỗi liên tiếp -> tự dừng, không lặp vô hạn
                self._live = False
                self._refresh_scan_button()
                err = ScanError(err.kind, f"{err.message} (đã tự dừng quét liên tục sau 3 lỗi liên tiếp)", err.hint, err.stderr)
        self._show_banner(f"Scan không thành công: {err.message} {err.hint}", "error")

    def _show_banner(self, text: str, level: str = "warn") -> None:
        self.banner.setProperty("level", level)
        self.banner.style().unpolish(self.banner); self.banner.style().polish(self.banner)
        self.banner.setText(text); self.banner.setVisible(bool(text))

    # ---- Filter / stats ----
    def apply_filters(self) -> None:
        band = self.cmb_band.currentText() if self.cmb_band.currentIndex() > 0 else None
        rows = filter_aps(self.all_aps, self.search.text(), band, self.cmb_sec.currentData(), self.chk_hidden.isChecked())
        sel = self.table.selectionModel().selectedRows()
        keep = self.model.ap_at(sel[0].row()).bssid if sel and self.model.ap_at(sel[0].row()) else None
        scroll = self.table.verticalScrollBar().value()
        self.model.set_rows(rows)                         # cập nhật tại chỗ: giữ dòng đang chọn và vị trí cuộn
        self.table.verticalScrollBar().setValue(scroll)
        self.lbl_count.setText(f"Hiển thị {len(rows)} / {len(self.all_aps)} AP")
        row = next((i for i, a in enumerate(self.model.rows()) if a.bssid == keep), None) if keep else None
        if row is not None:
            self.table.selectRow(row)
        self._on_select()

    def clear_filters(self) -> None:
        self.search.clear(); self.cmb_band.setCurrentIndex(0); self.cmb_sec.setCurrentIndex(0); self.chk_hidden.setChecked(True)

    def _update_stats(self) -> None:
        self.stats.update_from(self.all_aps, self.last_result, self._scan_no, self._live)

    def _column_menu(self, pos) -> None:
        menu = QMenu(self)
        for i, (title, _) in enumerate(COLUMNS):
            act = menu.addAction(title)
            act.setCheckable(True); act.setChecked(not self.table.isColumnHidden(i))
            act.setEnabled(i != 0)                            # luôn giữ cột SSID
            act.toggled.connect(lambda on, idx=i: self.table.setColumnHidden(idx, not on))
        menu.exec(self.table.horizontalHeader().mapToGlobal(pos))

    def _on_select(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        ap = self.model.ap_at(rows[0].row()) if rows else None
        self.details.show_ap(ap, self.history.get(ap.bssid) if ap else None)

    # ---- Export / diagnostics ----
    def export(self, fmt: str) -> None:
        if not self.all_aps:
            QMessageBox.information(self, "Xuất dữ liệu", "Chưa có dữ liệu scan để xuất."); return
        box = QMessageBox(self); box.setWindowTitle("Phạm vi xuất")
        box.setText("Xuất kết quả nào?"); box.setInformativeText(exporter.PRIVACY_WARNING)
        b_f = box.addButton("Đang lọc", QMessageBox.AcceptRole); b_a = box.addButton("Toàn bộ scan", QMessageBox.AcceptRole)
        box.addButton("Hủy", QMessageBox.RejectRole); box.exec()
        if box.clickedButton() not in (b_f, b_a):
            return
        aps, scope = (self.model.rows(), "filtered") if box.clickedButton() is b_f else (self.all_aps, "all")
        path, _ = QFileDialog.getSaveFileName(self, "Lưu file", f"wifi_scan.{fmt}", f"{fmt.upper()} (*.{fmt})")
        if not path:
            return
        try:
            out = exporter.export_json(aps, path, scope) if fmt == "json" else exporter.export_csv(aps, path)
        except exporter.ExportError as e:
            QMessageBox.critical(self, "Xuất thất bại", str(e)); return
        QMessageBox.information(self, "Xuất thành công", f"Đã lưu {len(aps)} AP vào:\n{out}")

    def show_glossary(self) -> None:
        """Mở cửa sổ giải thích không chặn cửa sổ chính; nếu đã mở thì đưa lên trước."""
        if self._glossary is None or not self._glossary.isVisible():
            self._glossary = GlossaryDialog()          # không có parent: cửa sổ độc lập, kéo ra cạnh để xem song song
            self._glossary.show()
        else:
            self._glossary.raise_(); self._glossary.activateWindow()

    def show_diagnostics(self) -> None:
        text = diagnostics.format_report(self.last_result, self.last_error, self.model.rowCount())
        DiagnosticsDialog(text, self).exec()

    def closeEvent(self, event) -> None:
        self._live = False
        if self._glossary is not None:
            self._glossary.close()
        if self._thread is not None:
            self._thread.quit(); self._thread.wait(3000)
        super().closeEvent(event)