"""Giao diện scanner chung + chạy lệnh an toàn."""
from __future__ import annotations

import locale
import subprocess
import sys
from abc import ABC, abstractmethod
from typing import Optional

from .models import ScanResult, WifiInterface


class ScanError(Exception):
    """kind: missing_executable | timeout | permission | os_error | command_failed | no_adapter |
    adapter_disabled | service_down | location_denied | unsupported | api_error | parse_error | internal"""

    def __init__(self, kind: str, message: str, hint: str = "", stderr: str = "") -> None:
        super().__init__(message)
        self.kind, self.message, self.hint, self.stderr = kind, message, hint, stderr


def decode_output(data: Optional[bytes]) -> str:
    if not data:
        return ""
    for enc in ("utf-8", locale.getpreferredencoding(False)):
        try:
            return data.decode(enc).lstrip("\ufeff")
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


def run_command(args: list[str], timeout: float = 15.0) -> str:
    kwargs = {"creationflags": 0x08000000} if sys.platform == "win32" else {}  # CREATE_NO_WINDOW
    try:
        proc = subprocess.run(args, capture_output=True, timeout=timeout, check=True, **kwargs)
    except FileNotFoundError as e:
        raise ScanError("missing_executable", f"Không tìm thấy lệnh '{args[0]}'.",
                        "Cài đặt công cụ tương ứng hoặc kiểm tra biến PATH.") from e
    except subprocess.TimeoutExpired as e:
        raise ScanError("timeout", f"Lệnh '{args[0]}' quá thời gian chờ ({timeout:g}s).",
                        "Thử quét lại; kiểm tra dịch vụ Wi-Fi/driver.") from e
    except subprocess.CalledProcessError as e:
        err = decode_output(e.stderr).strip()
        raise ScanError("command_failed", f"Lệnh '{args[0]}' thất bại (mã {e.returncode}).", stderr=err) from e
    except PermissionError as e:
        raise ScanError("permission", f"Không đủ quyền chạy '{args[0]}'.", "Kiểm tra quyền thực thi.") from e
    except OSError as e:
        raise ScanError("os_error", f"Lỗi hệ điều hành khi chạy '{args[0]}': {e}") from e
    return decode_output(proc.stdout)


class BaseScanner(ABC):
    os_name = ""

    @abstractmethod
    def list_interfaces(self) -> list[WifiInterface]: ...

    @abstractmethod
    def scan(self, interface: Optional[str] = None, timeout: float = 20.0) -> ScanResult: ...
