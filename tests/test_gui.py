import os
import threading
import time
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
try:
    from PySide6.QtWidgets import QApplication
    HAVE_QT = True
except ImportError:
    HAVE_QT = False

from app.models import AccessPoint, ScanResult
from app.scanner_base import BaseScanner, ScanError


class FakeScanner(BaseScanner):
    os_name = "Fake"

    def __init__(self, fail=False, count=2):
        self.fail, self.count, self.thread = fail, count, None

    def list_interfaces(self):
        return []

    def scan(self, interface=None, timeout=20.0):
        self.thread = threading.current_thread()
        time.sleep(0.05)
        if self.fail:
            raise ScanError("timeout", "hết thời gian", "thử lại")
        aps = [AccessPoint(ssid=f"n{i}", bssid=f"AA:BB:CC:00:00:0{i}", signal_percent=50 + i, band="5 GHz")
               for i in range(self.count)]
        return ScanResult(aps=aps, method="fake", source_os="Fake", source_count=self.count, timestamp="t")


@unittest.skipUnless(HAVE_QT, "PySide6 chưa cài")
class GuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def run_scan(self, scanner):
        from app.ui.main_window import MainWindow
        w = MainWindow(scanner)
        w.start_scan()
        self.assertFalse(w.btn_scan.isEnabled())
        w.start_scan()                                   # lần gọi thứ hai bị chặn
        end = time.time() + 5
        while w._thread is not None and time.time() < end:
            self.app.processEvents(); time.sleep(0.01)
        self.app.processEvents()
        return w

    def test_success_stops_spinner_and_worker_off_main_thread(self):
        s = FakeScanner()
        w = self.run_scan(s)
        self.assertTrue(w.spinner.isHidden())
        self.assertTrue(w.btn_scan.isEnabled())
        self.assertEqual(w.model.rowCount(), 2)
        self.assertIsNot(s.thread, threading.main_thread())
        self.assertEqual(w.model.ap_at(0).ssid, "n1")    # mặc định: tín hiệu mạnh nhất trước

    def test_failure_stops_spinner_and_shows_message(self):
        w = self.run_scan(FakeScanner(fail=True))
        self.assertTrue(w.spinner.isHidden())
        self.assertTrue(w.btn_scan.isEnabled())
        self.assertFalse(w.banner.isHidden())
        self.assertIn("không thành công", w.banner.text())

    def test_zero_ap_is_explained_and_filter_keeps_source(self):
        w = self.run_scan(FakeScanner(count=0))
        self.assertIn("không tìm thấy AP", w.banner.text())
        w = self.run_scan(FakeScanner(count=2))
        w.search.setText("n0")
        self.assertEqual(w.model.rowCount(), 1)
        self.assertEqual(len(w.all_aps), 2)              # lọc không đổi dữ liệu gốc
        self.assertIn("1 / 2", w.lbl_count.text())


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(HAVE_QT, "PySide6 chưa cài")
class GlossaryTests(unittest.TestCase):
    def test_every_column_has_tooltip_and_glossary_entry(self):
        from app.ui.glossary import glossary_html, tooltip_for
        from app.ui.network_table import COLUMNS
        for title, _ in COLUMNS:
            self.assertTrue(tooltip_for(title), title)
            self.assertIn(title, glossary_html())


@unittest.skipUnless(HAVE_QT, "PySide6 chưa cài")
class LiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_live_scan_repeats_without_overlap_and_keeps_history(self):
        from app.ui.main_window import MainWindow

        class Counting(FakeScanner):
            active = 0; overlap = False; calls = 0
            def scan(self, interface=None, timeout=20.0):
                Counting.active += 1; Counting.calls += 1
                Counting.overlap |= Counting.active > 1
                try:
                    return super().scan(interface, timeout)
                finally:
                    Counting.active -= 1
        w = MainWindow(Counting())
        w._interval_ms = lambda: 30
        w.btn_scan.click()                               # bấm Quét = bắt đầu quét liên tục
        self.assertIn("Dừng", w.btn_scan.text())
        end = time.time() + 8
        while Counting.calls < 3 and time.time() < end:
            self.app.processEvents(); time.sleep(0.01)
        w.table.selectRow(0)
        w.btn_scan.click()                               # bấm lần nữa = dừng
        end = time.time() + 3
        while w._thread is not None and time.time() < end:
            self.app.processEvents(); time.sleep(0.01)
        calls = Counting.calls
        for _ in range(30):
            self.app.processEvents(); time.sleep(0.01)
        self.assertGreaterEqual(calls, 3)
        self.assertFalse(Counting.overlap)
        self.assertEqual(Counting.calls, calls)          # sau khi dừng không quét thêm
        self.assertTrue(w.btn_scan.isEnabled())
        self.assertGreaterEqual(len(w.history["AA:BB:CC:00:00:01"]), 3)
        self.assertIn("Min / Max", w.details.toPlainText())

        self.assertEqual(w.stats.cards["total"].value.text(), "2")
        self.assertIn("Lần đo", w.stats.lbl_info.text())


@unittest.skipUnless(HAVE_QT, "PySide6 chưa cài")
class ColumnTests(unittest.TestCase):
    def test_default_hidden_and_delta_format(self):
        from app.ui.main_window import MainWindow
        from app.ui.network_table import COLUMNS, format_delta
        app = QApplication.instance() or QApplication([])
        w = MainWindow(FakeScanner())
        hidden = {k for i, (_, k) in enumerate(COLUMNS) if w.table.isColumnHidden(i)}
        self.assertEqual(hidden, {"vendor", "first_seen", "last_seen"})
        self.assertEqual(format_delta(AccessPoint(signal_dbm=-50.0, signal_delta=3.0)), "▲ +3 dBm")
        self.assertEqual(format_delta(AccessPoint(signal_percent=50, signal_delta=-5.0)), "▼ -5 %")
        self.assertEqual(format_delta(AccessPoint(signal_percent=50)), "N/A")
