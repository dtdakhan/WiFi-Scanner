import platform

from .scanner_base import BaseScanner, ScanError


def get_scanner() -> BaseScanner:
    system = platform.system()
    if system == "Windows":
        from .scanner_windows import WindowsScanner
        return WindowsScanner()
    if system == "Linux":
        from .scanner_linux import LinuxScanner
        return LinuxScanner()
    if system == "Darwin":
        from .scanner_macos import MacScanner
        return MacScanner()
    raise ScanError("unsupported", f"Hệ điều hành '{system}' chưa được hỗ trợ.")
