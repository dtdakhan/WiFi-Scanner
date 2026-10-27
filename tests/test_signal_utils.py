import unittest

from app.models import AccessPoint
from app.signal_utils import band_from_frequency, channel_from_frequency, format_signal, sort_by_signal


class SignalTests(unittest.TestCase):
    def test_bands_and_channels(self):
        self.assertEqual(band_from_frequency(2437), "2.4 GHz")
        self.assertEqual(channel_from_frequency(2437, "2.4 GHz"), 6)
        self.assertEqual(channel_from_frequency(2484, "2.4 GHz"), 14)
        self.assertEqual(band_from_frequency(5180), "5 GHz")
        self.assertEqual(channel_from_frequency(5180, "5 GHz"), 36)

    def test_6ghz_channel_not_confused_with_5ghz(self):
        self.assertEqual(band_from_frequency(5955), "6 GHz")
        self.assertEqual(channel_from_frequency(5955, "6 GHz"), 1)
        self.assertEqual(channel_from_frequency(5180, "6 GHz"), None)   # band sai -> không suy ra
        self.assertEqual(channel_from_frequency(5935, "6 GHz"), 2)

    def test_invalid(self):
        self.assertIsNone(band_from_frequency(None))
        self.assertIsNone(band_from_frequency(900))
        self.assertIsNone(channel_from_frequency(2413, "2.4 GHz"))

    def test_sort_never_mixes_units(self):
        a = AccessPoint(ssid="a", signal_percent=99)
        b = AccessPoint(ssid="b", signal_dbm=-80)
        c = AccessPoint(ssid="c", signal_dbm=-40)
        d = AccessPoint(ssid="d")
        self.assertEqual([x.ssid for x in sort_by_signal([d, a, b, c])], ["c", "b", "a", "d"])
        self.assertEqual(format_signal(a), "99%")
        self.assertEqual(format_signal(b), "-80 dBm")
        self.assertEqual(format_signal(d), "N/A")


if __name__ == "__main__":
    unittest.main()
