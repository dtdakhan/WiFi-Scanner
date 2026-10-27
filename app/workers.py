"""Worker chạy scan ngoài GUI thread. Chỉ phát tín hiệu; không đụng widget."""
from __future__ import annotations

import logging
from typing import Optional

from PySide6.QtCore import QObject, Signal, Slot

from .scanner_base import BaseScanner, ScanError

log = logging.getLogger(__name__)


class ScanWorker(QObject):
    progress = Signal(str)
    succeeded = Signal(object)   # ScanResult
    failed = Signal(object)      # ScanError

    def __init__(self, scanner: BaseScanner, interface: Optional[str], timeout: float) -> None:
        super().__init__()
        self._scanner, self._interface, self._timeout = scanner, interface, timeout

    @Slot()
    def run(self) -> None:
        try:
            self.progress.emit("Đang quét các Access Point lân cận...")
            result = self._scanner.scan(self._interface, self._timeout)
        except ScanError as e:
            log.error("Scan lỗi [%s]: %s", e.kind, e.message)
            self.failed.emit(e)
        except Exception as e:  # noqa: BLE001 - chốt chặn DUY NHẤT ở ranh giới worker: log traceback + báo lỗi
            log.exception("Lỗi không mong đợi trong worker")
            self.failed.emit(ScanError("internal", f"Lỗi nội bộ: {e}", "Chạy với --debug để xem traceback."))
        else:
            self.succeeded.emit(result)
