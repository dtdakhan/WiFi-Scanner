"""Windows: Native Wi-Fi API (wlanapi.dll qua ctypes) là đường chính; `netsh wlan show networks mode=bssid`
là fallback có cảnh báo. KHÔNG dùng profiles. Phần native CHƯA được xác minh trên phần cứng thật."""
from __future__ import annotations

import ctypes
import logging
import re
import sys
import threading
import time
from ctypes import POINTER, Structure, byref, c_int32, c_ubyte, c_uint16, c_uint32, c_uint64, c_void_p, c_wchar
from datetime import datetime
from typing import Optional

from .models import AccessPoint, ScanResult, WifiInterface
from .normalizer import finalize_ap, mark_connected
from .scanner_base import BaseScanner, ScanError, run_command

log = logging.getLogger(__name__)

LOCATION_HINT = "Windows 11 có thể chặn scan khi Location tắt: Settings → Privacy & security → Location → bật."
PHY = {1: "FHSS", 2: "DSSS", 3: "IR", 4: "802.11a", 5: "802.11b", 6: "802.11g",
       7: "802.11n", 8: "802.11ac", 9: "802.11ad", 10: "802.11ax", 11: "802.11be"}
STATE = {0: "not_ready", 1: "connected", 2: "ad_hoc", 3: "disconnecting", 4: "disconnected",
         5: "associating", 6: "discovering", 7: "authenticating"}


# ---------- Cấu trúc ctypes (kích thước cố định, độc lập kiểu wintypes) ----------
class GUID(Structure):
    _fields_ = [("Data1", c_uint32), ("Data2", c_uint16), ("Data3", c_uint16), ("Data4", c_ubyte * 8)]


class DOT11_SSID(Structure):
    _fields_ = [("uSSIDLength", c_uint32), ("ucSSID", c_ubyte * 32)]


class WLAN_INTERFACE_INFO(Structure):
    _fields_ = [("InterfaceGuid", GUID), ("strInterfaceDescription", c_wchar * 256), ("isState", c_uint32)]


class WLAN_INTERFACE_INFO_LIST(Structure):
    _fields_ = [("dwNumberOfItems", c_uint32), ("dwIndex", c_uint32), ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)]


class WLAN_RATE_SET(Structure):
    _fields_ = [("uRateSetLength", c_uint32), ("usRateSet", c_uint16 * 126)]


class WLAN_BSS_ENTRY(Structure):
    _fields_ = [("dot11Ssid", DOT11_SSID), ("uPhyId", c_uint32), ("dot11Bssid", c_ubyte * 6),
                ("dot11BssType", c_int32), ("dot11BssPhyType", c_int32), ("lRssi", c_int32),
                ("uLinkQuality", c_uint32), ("bInRegDomain", c_ubyte), ("usBeaconPeriod", c_uint16),
                ("ullTimestamp", c_uint64), ("ullHostTimestamp", c_uint64), ("usCapabilityInformation", c_uint16),
                ("ulChCenterFrequency", c_uint32), ("wlanRateSet", WLAN_RATE_SET),
                ("ulIeOffset", c_uint32), ("ulIeSize", c_uint32)]


class WLAN_BSS_LIST(Structure):
    _fields_ = [("dwTotalSize", c_uint32), ("dwNumberOfItems", c_uint32), ("wlanBssEntries", WLAN_BSS_ENTRY * 1)]


class WLAN_NOTIFICATION_DATA(Structure):
    _fields_ = [("NotificationSource", c_uint32), ("NotificationCode", c_uint32), ("InterfaceGuid", GUID),
                ("dwDataSize", c_uint32), ("pData", c_void_p)]


class WLAN_CONN_PREFIX(Structure):  # phần đầu của WLAN_CONNECTION_ATTRIBUTES tới dot11Bssid
    _fields_ = [("isState", c_uint32), ("wlanConnectionMode", c_uint32), ("strProfileName", c_wchar * 256),
                ("dot11Ssid", DOT11_SSID), ("dot11BssType", c_int32), ("dot11Bssid", c_ubyte * 6)]


# ---------- Parse security từ Information Elements (thuần Python, test được) ----------
_AKM = {1: "802.1X", 2: "PSK", 3: "FT-802.1X", 4: "FT-PSK", 5: "802.1X-SHA256", 6: "PSK-SHA256",
        8: "SAE", 9: "FT-SAE", 11: "Suite-B", 12: "Suite-B-192", 18: "OWE"}
_CIPHER = {1: "WEP-40", 2: "TKIP", 4: "CCMP", 5: "WEP-104", 8: "GCMP", 9: "GCMP-256", 10: "CCMP-256"}


def iter_ies(blob: bytes):
    i = 0
    while i + 2 <= len(blob):
        eid, ln = blob[i], blob[i + 1]
        body = blob[i + 2:i + 2 + ln]
        if len(body) < ln:
            raise ValueError("IE bị cắt ngắn")
        yield eid, body
        i += 2 + ln


def parse_rsn(body: bytes) -> tuple[list[str], list[str]]:
    """Trả về (akm_names, pairwise_cipher_names) từ RSN IE; ném ValueError nếu hỏng."""
    try:
        pos = 2 + 4                                   # version + group cipher
        pc = int.from_bytes(body[pos:pos + 2], "little"); pos += 2
        ciphers = [s for s in (body[pos + 4 * i:pos + 4 * i + 4] for i in range(pc))]
        pos += 4 * pc
        ac = int.from_bytes(body[pos:pos + 2], "little"); pos += 2
        akms = [body[pos + 4 * i:pos + 4 * i + 4] for i in range(ac)]
        if len(akms) != ac or any(len(s) != 4 for s in ciphers + akms) or pc == 0 and ac == 0:
            raise ValueError("RSN IE bị cắt")
    except IndexError as e:
        raise ValueError("RSN IE hỏng") from e
    oui = b"\x00\x0f\xac"
    return ([_AKM.get(s[3], f"AKM{s[3]}") for s in akms if s[:3] == oui],
            [_CIPHER.get(s[3], f"CIPHER{s[3]}") for s in ciphers if s[:3] == oui])


def label_security(akms: list[str]) -> str:
    s = set(akms)
    parts = []
    if s & {"PSK", "FT-PSK", "PSK-SHA256"}: parts.append("WPA2-Personal")
    if s & {"SAE", "FT-SAE"}: parts.append("WPA3-Personal")
    if s & {"802.1X", "FT-802.1X", "802.1X-SHA256"}: parts.append("WPA2-Enterprise")
    if s & {"Suite-B", "Suite-B-192"}: parts.append("WPA3-Enterprise")
    if "OWE" in s: parts.append("OWE")
    if not parts:
        return "RSN (" + ", ".join(sorted(s)) + ")" if s else "RSN"
    return "/".join(parts) if len(parts) == 2 and all(p.endswith("Personal") for p in parts) \
        else " + ".join(parts)


def parse_security(ies: bytes, privacy_bit: bool) -> tuple[Optional[str], Optional[str]]:
    """(security, cipher) theo bằng chứng trong IE; không đoán."""
    labels, ciphers = [], []
    try:
        for eid, body in iter_ies(ies):
            if eid == 48:
                akms, cs = parse_rsn(body)
                labels.append(label_security(akms)); ciphers += cs
            elif eid == 221 and body[:4] == b"\x00\x50\xf2\x01":
                labels.append("WPA")
    except ValueError as e:
        log.warning("IE security không phân tích được: %s", e)
        return None, None
    if labels:
        return " | ".join(dict.fromkeys(labels)), (", ".join(dict.fromkeys(ciphers)) or None)
    return ("Protected (no WPA/RSN IE: WEP or unspecified)" if privacy_bit else "Open"), None


def entry_to_ap(e: WLAN_BSS_ENTRY, ies: bytes, ts: str, iface: str) -> AccessPoint:
    ssid = bytes(e.dot11Ssid.ucSSID[:e.dot11Ssid.uSSIDLength]).decode("utf-8", errors="replace")
    security, cipher = parse_security(ies, bool(e.usCapabilityInformation & 0x10))
    ap = AccessPoint(
        ssid=ssid, bssid=":".join(f"{b:02X}" for b in e.dot11Bssid),
        signal_dbm=float(e.lRssi), signal_percent=int(e.uLinkQuality), signal_raw=f"{e.lRssi} dBm / {e.uLinkQuality}",
        frequency_mhz=round(e.ulChCenterFrequency / 1000) or None,     # API trả kHz
        security=security, security_scope="per_bssid", cipher=cipher,
        radio_type=PHY.get(e.dot11BssPhyType), interface_name=iface, source_os="Windows",
        source_method="WlanGetNetworkBssList", scan_timestamp=ts,
        raw={"phy": e.dot11BssPhyType, "host_ts": e.ullHostTimestamp, "cap": e.usCapabilityInformation})
    return finalize_ap(ap)


# ---------- Native WLAN ----------
def _enum_interfaces(dll, handle):
    plist = c_void_p()
    rc = dll.WlanEnumInterfaces(handle, None, byref(plist))
    if rc:
        raise ScanError("api_error", f"WlanEnumInterfaces lỗi {rc}.")
    lst = ctypes.cast(plist, POINTER(WLAN_INTERFACE_INFO_LIST)).contents
    infos = (WLAN_INTERFACE_INFO * lst.dwNumberOfItems).from_address(ctypes.addressof(lst.InterfaceInfo))
    out = [(GUID.from_buffer_copy(i.InterfaceGuid), i.strInterfaceDescription, STATE.get(i.isState, "?"))
           for i in infos]
    dll.WlanFreeMemory(plist)
    return out


def _native_scan(interface: Optional[str], timeout: float, result: ScanResult) -> None:
    if sys.platform != "win32":
        raise ScanError("unsupported", "wlanapi.dll chỉ có trên Windows.")
    try:
        dll = ctypes.WinDLL("wlanapi.dll")
    except OSError as e:
        raise ScanError("unsupported", f"Không nạp được wlanapi.dll: {e}") from e
    handle, ver = c_void_p(), c_uint32()
    rc = dll.WlanOpenHandle(2, None, byref(ver), byref(handle))
    if rc == 1062:
        raise ScanError("service_down", "Dịch vụ WLAN AutoConfig không chạy.", "Chạy: net start wlansvc")
    if rc:
        raise ScanError("api_error", f"WlanOpenHandle lỗi {rc}.")
    done, outcome = threading.Event(), {}
    cb_type = ctypes.WINFUNCTYPE(None, POINTER(WLAN_NOTIFICATION_DATA), c_void_p)

    def _cb(data, _ctx):                       # chạy trên thread của hệ điều hành: chỉ set Event
        n = data.contents
        if n.NotificationSource == 0x8 and n.NotificationCode in (7, 8):
            outcome[bytes(n.InterfaceGuid)] = n.NotificationCode
            done.set()
    cb = cb_type(_cb)                          # giữ tham chiếu tới khi hủy đăng ký
    try:
        dll.WlanRegisterNotification(handle, 0x8, False, cb, None, None, None)
        ifaces = _enum_interfaces(dll, handle)
        result.interfaces = [WifiInterface(d, d, s) for _, d, s in ifaces]
        if not ifaces:
            raise ScanError("no_adapter", "Không có wireless interface.", "Bật/cài driver Wi-Fi.")
        chosen = [x for x in ifaces if interface in (None, x[1])]
        if not chosen:
            raise ScanError("no_adapter", f"Không thấy interface '{interface}'.")
        ts = datetime.now().astimezone().isoformat(timespec="seconds")
        for guid, desc, state in chosen:
            result.adapter_state = state
            done.clear(); outcome.clear()
            rc = dll.WlanScan(handle, byref(guid), None, None, None)
            if rc == 5:
                raise ScanError("location_denied", "WlanScan bị từ chối (ERROR_ACCESS_DENIED).", LOCATION_HINT)
            if rc:
                raise ScanError("api_error", f"WlanScan lỗi {rc} trên '{desc}'.")
            if not done.wait(timeout):
                result.warnings.append(f"Không nhận thông báo scan hoàn tất sau {timeout:g}s trên '{desc}'; "
                                       "kết quả có thể là cache của hệ điều hành.")
            elif outcome.get(bytes(guid)) == 8:
                result.warnings.append(f"Scan thất bại trên '{desc}' (acm_scan_fail); kết quả có thể là cache.")
            pbss = c_void_p()
            rc = dll.WlanGetNetworkBssList(handle, byref(guid), None, 3, False, None, byref(pbss))
            if rc:
                raise ScanError("api_error", f"WlanGetNetworkBssList lỗi {rc}.")
            lst = ctypes.cast(pbss, POINTER(WLAN_BSS_LIST)).contents
            n = lst.dwNumberOfItems
            entries = (WLAN_BSS_ENTRY * n).from_address(ctypes.addressof(lst.wlanBssEntries))
            result.source_count += n
            for i in range(n):
                e = entries[i]
                try:
                    ies = ctypes.string_at(ctypes.addressof(e) + e.ulIeOffset, e.ulIeSize)
                    result.aps.append(entry_to_ap(e, ies, ts, desc))
                except ValueError as ex:
                    result.dropped.append(f"BSS {i}: {ex}")
            dll.WlanFreeMemory(pbss)
            conn = c_void_p(); size = c_uint32()
            if dll.WlanQueryInterface(handle, byref(guid), 7, None, byref(size), byref(conn), None) == 0:
                cur = ctypes.cast(conn, POINTER(WLAN_CONN_PREFIX)).contents
                mac = ":".join(f"{b:02X}" for b in cur.dot11Bssid)
                mark_connected([a for a in result.aps if a.interface_name == desc], mac, True)
                dll.WlanFreeMemory(conn)
            else:
                mark_connected([a for a in result.aps if a.interface_name == desc], None, True)
        result.timestamp = ts
    finally:
        dll.WlanRegisterNotification(handle, 0, False, None, None, None, None)   # hủy đăng ký trước khi đóng
        dll.WlanCloseHandle(handle, None)


# ---------- netsh fallback (độc lập ngôn ngữ: parse theo cấu trúc + giá trị) ----------
_SSID_RE = re.compile(r"^\s*SSID\s+\d+\s*:\s?(.*)$")
_BSSID_RE = re.compile(r"^\s*BSSID\s+\d+\s*:\s?(.*)$")
_FIELD_RE = re.compile(r"^\s+(.*?)\s+:\s?(.*)$")


def parse_netsh_networks(text: str, ts: str):
    """Trả về (aps, dropped, source_count). Nhãn bị dịch nên dựa vào thứ tự và dạng giá trị:
    trước BSSID: [loại mạng, xác thực, mã hóa]; trong BSSID: '%'->signal, '802.11*'->radio, 'x GHz'->band, số đầu tiên->channel."""
    aps, dropped, count = [], [], 0
    ssid: Optional[str] = None
    net: list[str] = []
    cur: Optional[dict] = None

    def flush():
        nonlocal cur, count
        if cur is None:
            return
        count += 1
        try:
            auth = net[1] if len(net) > 1 else None
            ap = AccessPoint(
                ssid=cur["ssid"], bssid=cur["bssid"], signal_percent=cur.get("pct"), signal_raw=cur.get("pct_raw"),
                channel=cur.get("ch"), band=cur.get("band", "Unknown"), security=auth, security_scope="per_ssid",
                cipher=net[2] if len(net) > 2 else None, radio_type=cur.get("radio"),
                source_os="Windows", source_method="netsh wlan show networks mode=bssid (fallback)",
                scan_timestamp=ts, raw={"network_fields": list(net)})
            aps.append(finalize_ap(ap))
        except ValueError as e:
            dropped.append(f"BSSID '{cur.get('bssid')}': {e}")
        cur = None

    for line in text.splitlines():
        m = _SSID_RE.match(line)
        if m:
            flush(); ssid, net = m.group(1).strip(), []
            continue
        m = _BSSID_RE.match(line)
        if m and ssid is not None:
            flush(); cur = {"ssid": ssid, "bssid": m.group(1).strip()}
            continue
        m = _FIELD_RE.match(line)
        if not m or ssid is None:
            continue
        val = m.group(2).strip()
        if cur is None:
            net.append(val)
        elif re.fullmatch(r"\d+\s*%", val) and "pct" not in cur:
            cur["pct"], cur["pct_raw"] = int(val.rstrip("% ").strip()), val
        elif val.startswith("802.11") and "radio" not in cur:
            cur["radio"] = val
        elif re.fullmatch(r"(2\.4|5|6)\s*GHz", val, re.I) and "band" not in cur:
            cur["band"] = val.upper().replace("GHZ", "GHz").replace(" ", " ")
        elif re.fullmatch(r"\d+", val) and "ch" not in cur:
            cur["ch"] = int(val)
    flush()
    return aps, dropped, count


def parse_netsh_connected_bssid(text: str) -> Optional[str]:
    m = re.search(r"^\s*BSSID\s*:\s*((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})\s*$", text, re.M)
    return m.group(1) if m else None


class WindowsScanner(BaseScanner):
    os_name = "Windows"

    def list_interfaces(self) -> list[WifiInterface]:
        if sys.platform != "win32":
            return []
        dll, handle, ver = ctypes.WinDLL("wlanapi.dll"), c_void_p(), c_uint32()
        if dll.WlanOpenHandle(2, None, byref(ver), byref(handle)):
            return []
        try:
            return [WifiInterface(d, d, st) for _, d, st in _enum_interfaces(dll, handle)]
        except ScanError:
            return []
        finally:
            dll.WlanCloseHandle(handle, None)

    def scan(self, interface: Optional[str] = None, timeout: float = 20.0) -> ScanResult:
        t0 = time.monotonic()
        result = ScanResult(method="WlanScan + WlanGetNetworkBssList (wlanapi.dll)", source_os="Windows",
                            interface=interface)
        try:
            _native_scan(interface, timeout, result)
        except ScanError as e:
            if e.kind not in ("unsupported", "api_error"):
                raise
            log.warning("Native WLAN API lỗi (%s); chuyển sang netsh.", e.message)
            result = ScanResult(method="netsh wlan show networks mode=bssid (FALLBACK)", source_os="Windows",
                                interface=interface,
                                warnings=[f"API native không dùng được ({e.message}); đang dùng fallback netsh: "
                                          "security theo SSID, không có dBm."])
            out = run_command(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout)
            ts = datetime.now().astimezone().isoformat(timespec="seconds")
            result.timestamp = ts
            result.aps, result.dropped, result.source_count = parse_netsh_networks(out, ts)
            try:
                cur = parse_netsh_connected_bssid(run_command(["netsh", "wlan", "show", "interfaces"], timeout))
                mark_connected(result.aps, cur, True)
            except ScanError as e2:
                result.warnings.append(f"Không xác định được trạng thái kết nối: {e2.message}")
        result.elapsed_s = time.monotonic() - t0
        return result

