"""macOS: CoreWLAN qua PyObjC. CHƯA xác minh trên máy thật. Từ macOS 14, SSID/BSSID bị che nếu app
chưa được cấp Location Services; script Python trần thường không xin được -> cần app bundle (xem README)."""
from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Optional

from .models import AccessPoint, ScanResult, WifiInterface
from .normalizer import finalize_ap, mark_connected
from .scanner_base import BaseScanner, ScanError

log = logging.getLogger(__name__)
BANDS = {1: "2.4 GHz", 2: "5 GHz", 3: "6 GHz"}
SECURITY = [("kCWSecurityNone", "Open"), ("kCWSecurityWEP", "WEP"), ("kCWSecurityWPAPersonal", "WPA-Personal"),
            ("kCWSecurityWPA2Personal", "WPA2-Personal"), ("kCWSecurityWPA3Personal", "WPA3-Personal"),
            ("kCWSecurityWPAEnterprise", "WPA-Enterprise"), ("kCWSecurityWPA2Enterprise", "WPA2-Enterprise"),
            ("kCWSecurityWPA3Enterprise", "WPA3-Enterprise"), ("kCWSecurityOWE", "OWE")]


def _load():
    try:
        import CoreWLAN
        return CoreWLAN
    except ImportError as e:
        raise ScanError("unsupported", "Thiếu PyObjC CoreWLAN.",
                        "pip install pyobjc-framework-CoreWLAN") from e


class MacScanner(BaseScanner):
    os_name = "macOS"

    def list_interfaces(self) -> list[WifiInterface]:
        cw = _load()
        names = cw.CWWiFiClient.sharedWiFiClient().interfaceNames() or []
        return [WifiInterface(str(n)) for n in names]

    def scan(self, interface: Optional[str] = None, timeout: float = 20.0) -> ScanResult:
        cw = _load()
        t0 = time.monotonic()
        client = cw.CWWiFiClient.sharedWiFiClient()
        iface = client.interfaceWithName_(interface) if interface else client.interface()
        if iface is None:
            raise ScanError("no_adapter", "Không có Wi-Fi interface.", "Kiểm tra Wi-Fi có bật không.")
        if not iface.powerOn():
            raise ScanError("adapter_disabled", "Wi-Fi đang tắt.", "Bật Wi-Fi trong System Settings.")
        nets, err = iface.scanForNetworksWithName_error_(None, None)
        if err is not None:
            raise ScanError("api_error", f"CoreWLAN scan lỗi: {err.localizedDescription()}")
        ts = datetime.now().astimezone().isoformat(timespec="seconds")
        name = str(iface.interfaceName())
        result = ScanResult(method="CoreWLAN scanForNetworksWithName", source_os="macOS", interface=name,
                            interfaces=[WifiInterface(name)], adapter_state="power on", timestamp=ts)
        nets = list(nets or [])
        result.source_count = len(nets)
        for n in nets:
            try:
                ch = n.wlanChannel()
                sec = next((label for const, label in SECURITY
                            if hasattr(cw, const) and n.supportsSecurity_(getattr(cw, const))), None)
                ap = AccessPoint(
                    ssid=n.ssid(), bssid=n.bssid(), signal_dbm=float(n.rssiValue()), signal_raw=str(n.rssiValue()),
                    channel=int(ch.channelNumber()) if ch else None,
                    band=BANDS.get(int(ch.channelBand()), "Unknown") if ch else "Unknown",
                    security=sec, security_scope="per_bssid", interface_name=name,
                    source_os="macOS", source_method="CoreWLAN", scan_timestamp=ts)
                result.aps.append(finalize_ap(ap))
            except (ValueError, TypeError) as e:     # bssid None khi bị che -> ValueError từ normalize_mac
                result.dropped.append(f"{n.ssid()!r}: {e}")
        if nets and not result.aps:
            raise ScanError("location_denied", "Scan có kết quả nhưng SSID/BSSID bị che.",
                            "Cấp Location Services cho ứng dụng (cần app bundle có NSLocationUsageDescription).")
        mark_connected(result.aps, iface.bssid(), True)
        result.elapsed_s = time.monotonic() - t0
        return result
