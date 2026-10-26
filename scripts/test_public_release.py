#!/usr/bin/env python3
"""Regression checks for public-release refusal boundaries; synthetic inputs only."""
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
import test_keycloak_guard as fixtures

guard = fixtures.guard


class PublicReleaseTests(fixtures.GuardTests):
    def test_assessment_explicitly_denies_deployment_authority(self):
        result = self.assess()
        self.assertTrue(result["advisory_only"])
        self.assertFalse(result["authorizes_deployment"])

    def test_unknowns_and_high_overall_risk_hold(self):
        for key, value in (("unknowns", ["coverage incomplete"]),
                           ("overall_risk", "high"), ("overall_risk", "critical")):
            with self.subTest(key=key, value=value):
                review = self.review()
                review[key] = value
                self.assertEqual(self.assess(review=review)["state"], "HOLD_FOR_SECURITY")

    def test_clone_and_restore_prerequisites_hold(self):
        for key in ("clone_available", "restore_tested"):
            with self.subTest(key=key):
                record = self.input()
                record["environment"]["database"][key] = False
                self.assertEqual(self.assess(input_record=record)["state"], "HOLD_FOR_SECURITY")

    def test_duplicate_json_keys_refuse(self):
        evidence = self.root / "ambiguous.json"
        for text in ('{"schema":"one","schema":"two"}', '{"nested":{"x":1,"x":2}}'):
            evidence.write_text(text)
            with self.assertRaisesRegex(guard.Refused, "duplicate JSON"):
                guard.load(evidence)

    def test_dangling_output_symlink_refuses(self):
        target = self.root / "unintended.json"
        output = self.root / "output.json"
        output.symlink_to(target)
        with self.assertRaisesRegex(guard.Refused, "regular file"):
            guard.write_json(output, {"synthetic": True})
        self.assertFalse(target.exists())

    def test_readiness_cli_never_creates_approval(self):
        output = self.root / "approval.json"
        result = subprocess.run([
            sys.executable, str(Path(__file__).with_name("keycloak_guard.py")), "readiness",
            "--assessment", str(self.root / "absent-assessment.json"),
            "--rehearsal", str(self.root / "absent-rehearsal.json"), "--output", str(output),
        ], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("readiness is disabled", result.stderr)
        self.assertFalse(output.exists())

    def test_forged_readiness_input_never_escalates(self):
        assessment = self.write("forged.json", {"state": "READY_FOR_REHEARSAL"})
        with self.assertRaisesRegex(guard.Refused, "readiness is disabled"):
            guard.readiness(SimpleNamespace(assessment=assessment))


if __name__ == "__main__":
    import unittest
    unittest.main(verbosity=2)
