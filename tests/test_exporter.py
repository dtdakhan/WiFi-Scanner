import csv
import json
import os
import tempfile
import unittest

from app.exporter import ExportError, export_csv, export_json
from app.models import AccessPoint

APS = [AccessPoint(ssid="Phở 24, \"quote\"", bssid="AA:BB:CC:00:00:01", signal_dbm=-50.0, band="5 GHz"),
       AccessPoint(ssid="", bssid="AA:BB:CC:00:00:02", is_hidden=True)]


class ExportTests(unittest.TestCase):
    def test_json_unicode_and_no_secrets(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.json")
            export_json(APS, p, "filtered")
            raw = open(p, encoding="utf-8").read()
            self.assertIn("Phở 24", raw)
            data = json.loads(raw)
            self.assertEqual(data["scope"], "filtered")
            self.assertIsNone(data["access_points"][0]["channel"])
            self.assertNotIn("password", raw.lower())

    def test_csv_header_and_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.csv")
            export_csv(APS, p)
            rows = list(csv.DictReader(open(p, encoding="utf-8-sig", newline="")))
            self.assertEqual(rows[0]["ssid"], 'Phở 24, "quote"')
            self.assertEqual(rows[1]["is_hidden"], "True")
            self.assertEqual(rows[0]["channel"], "")

    def test_bad_path(self):
        with self.assertRaises(ExportError):
            export_json(APS, "/nonexistent_dir_xyz/a.json")
        with self.assertRaises(ExportError):
            export_csv(APS, "/nonexistent_dir_xyz/a.csv")


if __name__ == "__main__":
    unittest.main()
