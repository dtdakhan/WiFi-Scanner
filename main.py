"""Điểm khởi chạy: GUI mặc định; --diagnose / --export dùng chung backend với GUI."""
from __future__ import annotations

import argparse
import logging
import sys

from app import diagnostics, exporter
from app.scanner_base import ScanError
from app.scanner_factory import get_scanner


def cli(args: argparse.Namespace) -> int:
    try:
        result = get_scanner().scan()
    except ScanError as e:
        print(diagnostics.format_report(None, e)); return 2
    if args.diagnose:
        print(diagnostics.format_report(result))
    if args.export:
        try:
            out = exporter.export_csv(result.aps, args.export) if args.export.lower().endswith(".csv") \
                else exporter.export_json(result.aps, args.export)
        except exporter.ExportError as e:
            print(e, file=sys.stderr); return 3
        print(f"Đã xuất {len(result.aps)} AP -> {out}\n{exporter.PRIVACY_WARNING}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Wi-Fi Scanner (quét thụ động AP lân cận)")
    p.add_argument("--diagnose", action="store_true", help="quét và in báo cáo chẩn đoán (không mở GUI)")
    p.add_argument("--debug", action="store_true", help="bật log DEBUG")
    p.add_argument("--export", metavar="PATH", help="quét và xuất ra .json hoặc .csv (không mở GUI)")
    args = p.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if args.diagnose or args.export:
        return cli(args)
    from PySide6.QtWidgets import QApplication, QMessageBox
    from app.ui.main_window import MainWindow
    qt = QApplication(sys.argv)
    try:
        scanner = get_scanner()
    except ScanError as e:
        QMessageBox.critical(None, "Wi-Fi Scanner", f"{e.message} {e.hint}"); return 2
    win = MainWindow(scanner); win.show()
    return qt.exec()


if __name__ == "__main__":
    sys.exit(main())
