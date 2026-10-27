import unittest

from app.models import AccessPoint
from app.normalizer import filter_aps, finalize_ap, mark_connected, normalize_mac, sort_aps


def ap(ssid, bssid, **kw):
    return AccessPoint(ssid=ssid, bssid=bssid, **kw)


class NormalizerTests(unittest.TestCase):
    def test_mac(self):
        self.assertEqual(normalize_mac("aa-bb-cc-00-00-01"), "AA:BB:CC:00:00:01")
        with self.assertRaises(ValueError):
            normalize_mac("zz")

    def test_finalize_derives_only_from_frequency(self):
        a = finalize_ap(ap("x", "aa:bb:cc:00:00:01", frequency_mhz=5180))
        self.assertEqual((a.band, a.channel), ("5 GHz", 36))
        b = finalize_ap(ap("x", "aa:bb:cc:00:00:02"))
        self.assertEqual((b.band, b.channel, b.security, b.radio_type), ("Unknown", None, None, None))

    def test_hidden_not_guessed(self):
        h = finalize_ap(ap("", "aa:bb:cc:00:00:03"))
        self.assertTrue(h.is_hidden)
        self.assertEqual(h.ssid, "")

    def test_same_ssid_kept_separate(self):
        aps = [finalize_ap(ap("Net", f"aa:bb:cc:00:00:0{i}")) for i in (1, 2)]
        self.assertEqual(len({a.bssid for a in aps}), 2)

    def test_connected_by_bssid_not_ssid(self):
        aps = [finalize_ap(ap("Net", "aa:bb:cc:00:00:01")), finalize_ap(ap("Net", "aa:bb:cc:00:00:02"))]
        mark_connected(aps, "AA:BB:CC:00:00:02", True)
        self.assertEqual([a.is_connected for a in aps], [False, True])
        mark_connected(aps, None, False)             # không xác định -> giữ nguyên
        self.assertEqual([a.is_connected for a in aps], [False, True])

    def test_filter_and_unicode_search(self):
        aps = [finalize_ap(ap("Phở Hà Nội", "aa:bb:cc:00:00:01", frequency_mhz=2437, security="WPA2")),
               finalize_ap(ap("Cafe", "aa:bb:cc:00:00:02", frequency_mhz=5180, security="Open")),
               finalize_ap(ap("", "aa:bb:cc:00:00:03"))]
        orig = list(aps)
        self.assertEqual(len(filter_aps(aps, "phở")), 1)
        self.assertEqual(len(filter_aps(aps, "00:00:02")), 1)
        self.assertEqual(len(filter_aps(aps, band="5 GHz")), 1)
        self.assertEqual(len(filter_aps(aps, security="unknown")), 1)
        self.assertEqual(len(filter_aps(aps, show_hidden=False)), 2)
        self.assertEqual(aps, orig)                  # dữ liệu gốc không đổi

    def test_sort_missing_last(self):
        aps = [ap("b", "1", channel=None), ap("a", "2", channel=6), ap("c", "3", channel=1)]
        self.assertEqual([a.ssid for a in sort_aps(aps, "channel", False)], ["c", "a", "b"])
        self.assertEqual([a.ssid for a in sort_aps(aps, "channel", True)], ["a", "c", "b"])
        self.assertEqual(sort_aps([ap("Z", "1"), ap("a", "2")], "ssid", False)[0].ssid, "a")


if __name__ == "__main__":
    unittest.main()


class AnalyticsTests(unittest.TestCase):
    def test_annotate(self):
        from app.analytics import annotate
        from app.vendor import LAA_LABEL, VendorDB, parse_oui
        db = VendorDB(parse_oui("00-BB-CC   (hex)\t\tAcme Networks\n"))
        a = finalize_ap(ap("a", "00:BB:CC:00:00:01", frequency_mhz=2437, signal_dbm=-50.0))
        b = finalize_ap(ap("b", "00:BB:CC:00:00:02", frequency_mhz=2437, signal_percent=70))
        c = finalize_ap(ap("c", "02:BB:CC:00:00:03", frequency_mhz=5180, signal_dbm=-60.0))
        seen = {}
        annotate([a, b, c], {"00:BB:CC:00:00:01": ("dBm", -55.0), "00:BB:CC:00:00:02": ("dBm", -40.0)}, seen, "10:00:00", db)
        self.assertEqual(a.signal_delta, 5.0)
        self.assertIsNone(b.signal_delta)             # khác đơn vị: không so
        self.assertIsNone(c.signal_delta)             # chưa có lần đo trước
        self.assertEqual((a.channel_ap_count, b.channel_ap_count, c.channel_ap_count), (2, 2, 1))
        self.assertEqual((a.vendor, b.vendor, c.vendor), ("Acme Networks", "Acme Networks", LAA_LABEL))
        annotate([a], {}, seen, "10:00:05", db)
        self.assertEqual((a.first_seen, a.last_seen), ("10:00:00", "10:00:05"))

    def test_unknown_vendor_is_none_and_unknown_band_not_counted(self):
        from app.analytics import annotate
        from app.vendor import VendorDB
        x = finalize_ap(ap("x", "00:11:22:00:00:01"))
        annotate([x], {}, {}, "t", VendorDB())
        self.assertIsNone(x.vendor)
        self.assertIsNone(x.channel_ap_count)
