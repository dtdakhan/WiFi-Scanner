import os
import subprocess
import unittest
from unittest import mock

from app import diagnostics
from app.models import ScanResult
from app.scanner_base import ScanError, run_command
from app.scanner_linux import LinuxScanner, parse_nmcli_list, split_terse
from app.scanner_windows import parse_netsh_connected_bssid, parse_netsh_networks, parse_security

FX = os.path.join(os.path.dirname(__file__), "fixtures")
TS = "2026-01-01T00:00:00+07:00"


def fx(name):
    return open(os.path.join(FX, name), encoding="utf-8").read()


class NmcliTests(unittest.TestCase):
    def test_split_escape(self):
        self.assertEqual(split_terse(r"a\:b:c\\:d"), ["a:b", "c\\", "d"])

    def test_parse_fixture(self):
        aps, dropped, n = parse_nmcli_list(fx("nmcli_list.txt"), TS)
        self.assertEqual(n, 7)
        self.assertEqual(len(aps), 5)
        self.assertEqual(len(dropped), 2)                    # MAC sai + thiếu trường; các AP khác vẫn còn
        by = {a.bssid: a for a in aps}
        self.assertEqual(by["AA:BB:CC:00:00:01"].ssid, "Nhà Hàng Phở 24")
        self.assertTrue(by["AA:BB:CC:00:00:01"].is_connected)
        self.assertEqual(by["AA:BB:CC:00:00:02"].ssid, "Cafe: Wi-Fi")      # SSID chứa ':'
        self.assertEqual(by["AA:BB:CC:00:00:02"].band, "5 GHz")
        self.assertEqual(sum(1 for a in aps if a.ssid == "Nhà Hàng Phở 24"), 2)  # cùng SSID, khác BSSID
        hid = by["AA:BB:CC:00:00:04"]
        self.assertTrue(hid.is_hidden)
        self.assertEqual(hid.security, "Open")
        six = by["AA:BB:CC:00:00:06"]
        self.assertEqual((six.band, six.channel), ("6 GHz", 5))
        self.assertIsNone(six.signal_dbm)                    # nmcli chỉ có %
        self.assertEqual(six.signal_percent, 70)
        self.assertIsNone(six.radio_type)

    def test_empty(self):
        self.assertEqual(parse_nmcli_list("", TS), ([], [], 0))

    def test_unsaved_profile_networks_appear(self):
        """Parser chỉ dựa trên danh sách AP scan; không đọc profile nên mạng chưa lưu vẫn xuất hiện."""
        aps, _, _ = parse_nmcli_list(":NeverSeen:AA\\:BB\\:CC\\:00\\:00\\:99:Infra:1:2412 MHz:50:WPA2", TS)
        self.assertEqual(aps[0].ssid, "NeverSeen")


class NetshTests(unittest.TestCase):
    def test_english(self):
        aps, dropped, n = parse_netsh_networks(fx("netsh_en.txt"), TS)
        self.assertEqual(n, 4)
        self.assertEqual(len(aps), 3)
        self.assertEqual(len(dropped), 1)                    # BSSID 'not-a-mac'
        home = [a for a in aps if a.ssid == "HomeNet"]
        self.assertEqual(len(home), 2)
        a1 = next(a for a in home if a.bssid == "AA:BB:CC:00:00:01")
        self.assertEqual((a1.signal_percent, a1.channel, a1.band, a1.radio_type), (90, 36, "5 GHz", "802.11ax"))
        self.assertEqual(a1.security, "WPA2-Personal")
        self.assertEqual(a1.security_scope, "per_ssid")
        self.assertTrue(next(a for a in aps if a.bssid.endswith("03")).is_hidden)
        self.assertIsNone(a1.signal_dbm)

    def test_vietnamese_labels(self):
        aps, dropped, _ = parse_netsh_networks(fx("netsh_vi.txt"), TS)
        self.assertEqual(dropped, [])
        a = aps[0]
        self.assertEqual((a.ssid, a.signal_percent, a.channel, a.radio_type, a.security),
                         ("Nhà Tôi", 77, 44, "802.11ac", "WPA2-Personal"))

    def test_connected_bssid(self):
        self.assertEqual(parse_netsh_connected_bssid("    BSSID                  : aa:bb:cc:00:00:01\n"),
                         "aa:bb:cc:00:00:01")

    def test_empty(self):
        self.assertEqual(parse_netsh_networks("", TS), ([], [], 0))


class WindowsIeTests(unittest.TestCase):
    OUI = b"\x00\x0f\xac"

    def rsn(self, akm):
        body = b"\x01\x00" + self.OUI + b"\x04" + b"\x01\x00" + self.OUI + b"\x04" + b"\x01\x00" + self.OUI + bytes([akm])
        return bytes([48, len(body)]) + body

    def test_security(self):
        self.assertEqual(parse_security(self.rsn(2), True), ("WPA2-Personal", "CCMP"))
        self.assertEqual(parse_security(self.rsn(8), True)[0], "WPA3-Personal")
        self.assertEqual(parse_security(b"", False), ("Open", None))
        self.assertIn("Protected", parse_security(b"", True)[0])
        self.assertEqual(parse_security(b"\x30\x05\x01", True), (None, None))   # IE bị cắt -> không đoán


class CommandTests(unittest.TestCase):
    def check(self, exc, kind):
        with mock.patch("app.scanner_base.subprocess.run", side_effect=exc):
            with self.assertRaises(ScanError) as cm:
                run_command(["nmcli"])
        self.assertEqual(cm.exception.kind, kind)

    def test_errors(self):
        self.check(FileNotFoundError(), "missing_executable")
        self.check(subprocess.TimeoutExpired("nmcli", 1), "timeout")
        self.check(PermissionError(), "permission")
        self.check(OSError("x"), "os_error")
        self.check(subprocess.CalledProcessError(1, "nmcli", stderr=b"boom"), "command_failed")

    def test_linux_scan_with_mock(self):
        outputs = {"device": "wlan0:wifi:connected\n", "radio": "enabled\n", "list": fx("nmcli_list.txt")}

        def fake(args, timeout=15.0):
            return outputs["radio"] if args[1] == "radio" else outputs["list"] if "list" in args else outputs["device"]
        with mock.patch("app.scanner_linux.run_command", side_effect=fake):
            r = LinuxScanner().scan()
        self.assertEqual((r.source_count, r.parsed_count, len(r.dropped)), (7, 5, 2))

    def test_linux_no_adapter_and_disabled(self):
        with mock.patch("app.scanner_linux.run_command", return_value="eth0:ethernet:connected\n"):
            with self.assertRaises(ScanError) as cm:
                LinuxScanner().scan()
        self.assertEqual(cm.exception.kind, "no_adapter")
        with mock.patch("app.scanner_linux.run_command",
                        side_effect=lambda a, t=15.0: "wlan0:wifi:unavailable\n" if a[1] == "-t" else "disabled\n"):
            with self.assertRaises(ScanError) as cm:
                LinuxScanner().scan()
        self.assertEqual(cm.exception.kind, "adapter_disabled")

    def test_linux_polkit_denied(self):
        def fake(a, t=15.0):
            if "list" in a: raise ScanError("command_failed", "x", stderr="Error: Not authorized to control networking.")
            return "enabled\n" if a[1] == "radio" else "wlan0:wifi:connected\n"
        with mock.patch("app.scanner_linux.run_command", side_effect=fake):
            with self.assertRaises(ScanError) as cm:
                LinuxScanner().scan()
        self.assertEqual(cm.exception.kind, "permission")


class DiagnosticsTests(unittest.TestCase):
    def test_zero_records_is_not_parser_error(self):
        r = ScanResult(source_os="Linux", method="nmcli", source_count=0)
        self.assertIn("0 bản ghi", diagnostics.classify(r, None))
        self.assertIn("Gợi ý", diagnostics.format_report(r))

    def test_parse_failure_and_error(self):
        r = ScanResult(source_count=3, dropped=["a", "b", "c"])
        self.assertIn("PARSING", diagnostics.classify(r, None))
        self.assertIn("timeout", diagnostics.classify(None, ScanError("timeout", "x")))

    def test_sanitize_home(self):
        home = os.path.expanduser("~")
        self.assertNotIn(home, diagnostics.sanitize(f"error at {home}/x") if len(home) > 2 else "")


if __name__ == "__main__":
    unittest.main()
