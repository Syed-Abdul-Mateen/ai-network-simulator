import unittest
import tempfile
from ai_analysis import LogParser, FeatureExtractor, RootCauseAnalyzer, AttackPathBuilder

class TestAiAnalysis(unittest.TestCase):
    def test_log_parser(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("2023-08-01 12:34:56 [INFO] 192.168.1.10 -> 192.168.1.20: SSH login failed\n")
            f.write("invalid line\n")
            f.flush()
            parser = LogParser(f.name)
            events = parser.parse()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]['source_ip'], '192.168.1.10')
    
    def test_feature_extractor(self):
        events = [{"timestamp": "2023-08-01 12:34:56", "event_type": "log", "status": "INFO"}]
        extractor = FeatureExtractor(["timestamp", "event_type", "status"])
        df = extractor.extract(events)
        self.assertIn("hour", df.columns)
    
    def test_root_cause_analyzer(self):
        # Use dummy model path
        analyzer = RootCauseAnalyzer("nonexistent.pkl")
        results = analyzer.analyze(None)
        self.assertEqual(results[0]['cause'], "No model loaded")
    
    def test_attack_path_builder(self):
        events = [{"source_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "event_type": "login"}]
        builder = AttackPathBuilder()
        graph = builder.build(events)
        self.assertTrue(graph.has_edge("10.0.0.1", "10.0.0.2"))

if __name__ == '__main__':
    unittest.main()