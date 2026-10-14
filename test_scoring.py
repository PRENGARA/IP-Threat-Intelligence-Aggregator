import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ioc_lookup as tool

class AggregatorTests(unittest.TestCase):
    def test_ip_validation(self):
        self.assertTrue(tool.validate_ip("8.8.8.8"))
        self.assertTrue(tool.validate_ip("2001:db8::1"))
        self.assertFalse(tool.validate_ip("not-an-ip"))

    def test_empty_evidence_is_no_signal(self):
        score, band, reasons = tool.compute_severity({}, {}, {})
        self.assertEqual((score, band, reasons), (0, "Clean / No Signal", []))

    def test_abuseipdb_weight(self):
        score, band, reasons = tool.compute_severity({"ok":True,"abuse_confidence_score":50}, {}, {})
        self.assertEqual((score,band),(20,"Medium"))
        self.assertTrue(reasons)

    def test_critical_caps_at_100(self):
        abuse={"ok":True,"abuse_confidence_score":100,"is_tor":True}
        vt={"ok":True,"malicious_votes":20,"suspicious_votes":0,
            "related_hashes":[{"malicious_detections":80} for _ in range(25)]}
        otx={"ok":True,"pulse_count":20}
        self.assertEqual(tool.compute_severity(abuse,vt,otx)[:2],(100,"Critical"))

    def test_boundaries(self):
        # Each generated score comes solely from OTX pulses, except 1 from AbuseIPDB.
        self.assertEqual(tool.compute_severity({"ok":True,"abuse_confidence_score":2.5},{},{})[1],"Low")
        self.assertEqual(tool.compute_severity({}, {}, {"ok":True,"pulse_count":5})[1],"Medium")
        self.assertEqual(tool.compute_severity({"ok":True,"abuse_confidence_score":100},{"ok":True,"malicious_votes":2},{})[1],"High")

if __name__ == '__main__':
    unittest.main()
