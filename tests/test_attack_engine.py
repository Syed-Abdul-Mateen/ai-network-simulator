import unittest
from attack_engine import Scanner, Enumerator, CredentialAttacker, PrivilegeEscalator, LateralMover, MitreMapper

class TestAttackEngine(unittest.TestCase):
    def test_scanner(self):
        scanner = Scanner(["127.0.0.1"])
        ports = scanner.scan([80])
        self.assertIn("127.0.0.1", ports)
    
    def test_enumerator(self):
        targets = {"127.0.0.1": [445]}
        enum = Enumerator(targets)
        info = enum.enumerate()
        self.assertIn("shares", info["127.0.0.1"])
    
    def test_credential_attacker(self):
        targets = {"127.0.0.1": {"users": ["admin"], "services": []}}
        attacker = CredentialAttacker(targets, ["admin"])
        creds = attacker.attack()
        self.assertIsNotNone(creds["127.0.0.1"])
    
    def test_privilege_escalator(self):
        creds = {"127.0.0.1": {"user": "admin", "password": "admin"}}
        escalator = PrivilegeEscalator(creds)
        escalated = escalator.escalate()
        self.assertEqual(escalated["127.0.0.1"]["privilege"], "Administrator")
    
    def test_lateral_mover(self):
        creds = {"10.0.0.1": {"user": "admin", "password": "admin"}}
        network = {"10.0.0.1": ["10.0.0.2"]}
        mover = LateralMover(creds, network)
        moves = mover.move()
        self.assertIn("10.0.0.1 -> 10.0.0.2", moves)
    
    def test_mitre_mapper(self):
        mapper = MitreMapper("https://example.com/dummy")
        tid = mapper.map_step("Brute Force")
        self.assertEqual(tid, "T1110")

if __name__ == '__main__':
    unittest.main()