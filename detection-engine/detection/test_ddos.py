import os
import sys
import unittest
from datetime import datetime, timedelta

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from detection.ddos import DDoSDetector


class DDoSDetectorTests(unittest.TestCase):
    SOURCE = "198.51.100.25"

    def packet(self, at):
        return {"source_ip": self.SOURCE, "timestamp": at.isoformat()}

    def test_short_high_volume_burst_is_abnormal_not_ddos(self):
        detector = DDoSDetector(threshold=10, ddos_peak_threshold=30,
                                sustained_threshold=15, sustained_window_seconds=5)
        now = datetime.now()
        alerts = [detector.process_packet(self.packet(now)) for _ in range(10)]
        alert = next(item for item in alerts if item)
        self.assertEqual(alert["type"], "ABNORMAL_TRAFFIC")
        self.assertEqual(alert["severity"], "HIGH")

    def test_exceptional_peak_is_ddos(self):
        detector = DDoSDetector(threshold=10, ddos_peak_threshold=20,
                                sustained_threshold=50, sustained_window_seconds=5)
        now = datetime.now()
        alerts = [detector.process_packet(self.packet(now)) for _ in range(20)]
        self.assertEqual(alerts[-1]["type"], "DDOS")
        self.assertEqual(alerts[-1]["validation_reason"], "exceptional packet-rate peak")

    def test_sustained_rate_escalates_to_ddos(self):
        detector = DDoSDetector(threshold=100, ddos_peak_threshold=200,
                                sustained_threshold=4, sustained_window_seconds=5,
                                alert_cooldown_seconds=0)
        start = datetime.now()
        alert = None
        for second in range(6):
            for _ in range(4):
                candidate = detector.process_packet(
                    self.packet(start + timedelta(seconds=second))
                )
                if candidate:
                    alert = candidate
        self.assertEqual(alert["type"], "DDOS")
        self.assertEqual(alert["validation_reason"], "sustained elevated packet rate")

    def test_alerts_are_rate_limited_per_classification(self):
        detector = DDoSDetector(threshold=2, ddos_peak_threshold=10,
                                sustained_threshold=10, alert_cooldown_seconds=30)
        now = datetime.now()
        self.assertIsNone(detector.process_packet(self.packet(now)))
        self.assertEqual(detector.process_packet(self.packet(now))["type"], "ABNORMAL_TRAFFIC")
        self.assertIsNone(detector.process_packet(self.packet(now)))


if __name__ == "__main__":
    unittest.main()
