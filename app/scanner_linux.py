"""Linux: NetworkManager (nmcli). Chỉ có SIGNAL dạng %, không có dBm."""
from __future__ import annotations

import logging
import re
import time
from datetime import datetime
from typing import Optional

from .models import AccessPoint, ScanResult, WifiInterface
from .normalizer import finalize_ap, mark_connected
from .scanner_base import BaseScanner, ScanError, run_command

log = logging.getLogger(__name__)
FIELDS = "IN-USE,SSID,BSSID,MODE,CHAN,FREQ,SIGNAL,SECURITY"


def split_terse(line: str) -> list[str]:
    """Tách trường của `nmcli -t --escape yes`: chỉ tách ở ':' không bị escape; '\\:' và '\\\\' được giải mã."""
    fields: list[str] = []
    cur: list[str] = []
    i = 0
    while i < len(line):
        c = line[i]
        if c == "\\" and i + 1 < len(line):
            cur.append(line[i + 1])
            i += 2
            continue
        if c == ":":
            fields.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    fields.append("".join(cur))
    return fields


def parse_nmcli_list(text: str, ts: str, iface: Optional[str] = None):
    """Trả về (aps, dropped, source_count). Lỗi một dòng không làm mất các dòng khác."""
    aps: list[AccessPoint] = []
    dropped: list[str] = []
    count = 0
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        count += 1
        f = split_terse(line)
        if len(f) != 8:
            dropped.append(f"dòng {n}: số trường {len(f)} != 8")
            continue
        in_use, ssid, bssid, mode, chan, freq, sig, sec = f
        try:
            m = re.match(r"\s*(\d+)", freq)
            sec_clean = sec.strip()
            ap = AccessPoint(
                ssid=ssid, bssid=bssid,
                signal_percent=int(sig) if sig.strip() else None, signal_raw=sig or None,
                channel=int(chan) if chan.strip().isdigit() else None,
                frequency_mhz=int(m.group(1)) if m else None,
                security="Open" if sec_clean in ("", "--") else sec_clean, security_scope="per_bssid",
                is_connected=in_use.strip() == "*", interface_name=iface,
                source_os="Linux", source_method="nmcli", scan_timestamp=ts,
                raw={"line": line, "mode": mode},
            )
            aps.append(finalize_ap(ap))
        except ValueError as e:
            dropped.append(f"dòng {n}: {e}")
    return aps, dropped, count


def _reclassify(e: ScanError) -> ScanError:
    s = e.stderr.lower()
    table = [
        ("not authorized", "permission", "polkit từ chối quét Wi-Fi cho người dùng này."),
        ("not running", "service_down", "Khởi động NetworkManager: sudo systemctl start NetworkManager"),
        ("wi-fi is disabled", "adapter_disabled", "Bật Wi-Fi: nmcli radio wifi on"),
        ("no wi-fi device", "no_adapter", "Không thấy wireless interface do NetworkManager quản lý."),
    ]
    for needle, kind, hint in table:
        if needle in s:
            return ScanError(kind, e.message, hint, e.stderr)
    return e


class LinuxScanner(BaseScanner):
    os_name = "Linux"

    def list_interfaces(self) -> list[WifiInterface]:
        out = run_command(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device"])
        res = []
        for line in out.splitlines():
            f = split_terse(line)
            if len(f) >= 3 and f[1] == "wifi":
                res.append(WifiInterface(f[0], "", f[2]))
        return res

    def scan(self, interface: Optional[str] = None, timeout: float = 20.0) -> ScanResult:
        t0 = time.monotonic()
        try:
            ifaces = self.list_interfaces()
            if not ifaces:
                raise ScanError("no_adapter", "Không có wireless interface.", "Kiểm tra driver/phần cứng Wi-Fi.")
            radio = run_command(["nmcli", "radio", "wifi"]).strip()
            if radio.lower() == "disabled":
                raise ScanError("adapter_disabled", "Radio Wi-Fi đang tắt.", "Bật Wi-Fi: nmcli radio wifi on")
            result = ScanResult(method="nmcli device wifi list --rescan yes", source_os="Linux",
                                interface=interface, interfaces=ifaces, adapter_state=f"radio {radio}")
            base = ["nmcli", "-t", "--escape", "yes", "-f", FIELDS, "device", "wifi", "list"]
            tail = ["ifname", interface] if interface else []
            try:
                out = run_command(base + ["--rescan", "yes"] + tail, timeout)
            except ScanError as e:
                if "scanning not allowed" in e.stderr.lower():
                    result.warnings.append("NetworkManager giới hạn tần suất rescan; đang hiển thị kết quả "
                                           "scan gần nhất (có thể là cache).")
                    result.method = "nmcli device wifi list --rescan no"
                    out = run_command(base + ["--rescan", "no"] + tail, timeout)
                else:
                    raise
        except ScanError as e:
            raise _reclassify(e)
        ts = datetime.now().astimezone().isoformat(timespec="seconds")
        result.timestamp = ts
        result.aps, result.dropped, result.source_count = parse_nmcli_list(out, ts, interface)
        known = bool(result.aps)
        mark_connected(result.aps, next((a.bssid for a in result.aps if a.is_connected), None), known)
        result.elapsed_s = time.monotonic() - t0
        return result
