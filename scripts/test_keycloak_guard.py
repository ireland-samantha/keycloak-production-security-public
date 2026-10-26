#!/usr/bin/env python3
# Synthetic origin: OpenAI, GPT-6.1, via Codex. A human did not make this change directly, a system did.
"""Offline regression tests for the reusable Keycloak evidence gates."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
SKILL = HERE.parent
SPEC = importlib.util.spec_from_file_location("keycloak_guard", HERE / "keycloak_guard.py")
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)

OLD_COMMIT = "1" * 40
NEW_COMMIT = "2" * 40
OLD_DIGEST = "sha256:" + "a" * 64
NEW_DIGEST = "sha256:" + "b" * 64


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    @staticmethod
    def release(version, commit, digest):
        return {
            "version": version,
            "source_commit": commit,
            "upstream_image": "quay.io/keycloak/keycloak@" + digest,
            "upstream_platform_digest": digest,
            "image": "registry.example/keycloak/keycloak@" + digest,
            "platform_digest": digest,
        }

    def input(self, candidate="26.0.5"):
        return {
            "schema": "iam.keycloak.production-security/input-v1",
            "current": self.release("26.0.4", OLD_COMMIT, OLD_DIGEST),
            "candidate": self.release(candidate, NEW_COMMIT, NEW_DIGEST),
            "environment": {
                "database": {
                    "engine": "postgresql",
                    "version": "16",
                    "clone_available": True,
                    "restore_tested": True,
                },
                "topology": {"nodes": 2, "cache_mode": "distributed", "mixed_version_supported": False},
                "customizations": [{
                    "name": "tenant-policy",
                    "kind": "provider",
                    "source_revision": "commit:" + "3" * 40,
                    "compatibility_test": "compile and run authentication journeys against the candidate",
                }],
                "journeys": ["authorization code with PKCE", "refresh and logout", "client credentials"],
            },
            "policy": {
                "block_critical": True,
                "block_fixable_high": True,
                "automatic_patch_only": True,
                "minimum_stability_seconds": 600,
                "rpo_seconds": 60,
                "rto_seconds": 900,
            },
        }

    @staticmethod
    def risk(identifier, severity="medium"):
        return {
            "id": identifier,
            "severity": severity,
            "evidence": "server-spi/src/main/java/example/Provider.java:40",
            "impact": "The deployed provider may change behavior.",
            "recommendation": "Exercise the provider journey on a database clone.",
            "confidence": "high",
        }

    def review(self, candidate="26.0.5", decision="approve_rehearsal"):
        return {
            "schema": "iam.keycloak.production-security/review-v1",
            "current_version": "26.0.4",
            "current_source_commit": OLD_COMMIT,
            "current_image_digest": OLD_DIGEST,
            "current_platform_digest": OLD_DIGEST,
            "candidate_version": candidate,
            "candidate_source_commit": NEW_COMMIT,
            "candidate_image_digest": NEW_DIGEST,
            "candidate_platform_digest": NEW_DIGEST,
            "decision": decision,
            "overall_risk": "medium",
            "summary": "The patch closes exposure and needs a clone-backed compatibility rehearsal.",
            "risk_of_staying": [self.risk("CVE-fixture", "high")],
            "risk_of_upgrading": [self.risk("SPI-fixture")],
            "breaking_changes": [{
                "area": "provider SPI",
                "evidence": "services/src/main/java/example/Factory.java:18",
                "impact": "Factory initialization ordering changed.",
                "compatibility_test": "Start the exact provider and complete its login journey.",
            }],
            "blockers": [],
            "coverage": ["source diff: current tag to candidate tag", "container and dependency scan"],
            "unknowns": [],
            "migration_steps": ["Restore a sanitized clone and start blue.", "Start red on the migrated clone."],
            "rollback_steps": ["Prove snapshot restore before promotion."],
            "canary_checks": ["Complete synthetic login, refresh, logout, and client credentials."],
        }

    @staticmethod
    def trivy(image, *vulnerabilities):
        return {
            "SchemaVersion": 2,
            "ArtifactName": image,
            "Results": [{"Target": "fixture", "Vulnerabilities": list(vulnerabilities)}],
        }

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    @staticmethod
    def sbom(name):
        return {
            "bomFormat": "CycloneDX", "specVersion": "1.6",
            "components": [{"type": "application", "name": name, "version": "fixture"}],
        }

    def assess(self, input_record=None, review=None, current_scan=None, candidate_scan=None,
               candidate_sbom=None):
        input_record = input_record or self.input()
        paths = {
            "input": self.write("input.json", input_record),
            "review": self.write("review.json", review or self.review()),
            "trivy": self.write("current.json", current_scan or self.trivy(input_record["current"]["image"])),
            "candidate_trivy": self.write(
                "candidate.json", candidate_scan or self.trivy(input_record["candidate"]["image"])),
            "current_sbom": self.write("current-sbom.json", self.sbom("current")),
            "candidate_sbom": self.write(
                "candidate-sbom.json", self.sbom("candidate") if candidate_sbom is None else candidate_sbom),
            "scan_binding": self.root / "scan-binding.json",
            "source_binding": self.root / "source-binding.json",
            "source_name_status": self.root / "source-name-status.txt",
            "source_stat": self.root / "source-stat.txt",
            "output": self.root / "assessment.json",
            "github_output": None,
        }
        paths["source_name_status"].write_text("M\tservices/src/main/java/example/Factory.java\n", encoding="utf-8")
        paths["source_stat"].write_text("1 file changed, 1 insertion(+), 1 deletion(-)\n", encoding="utf-8")
        paths["source_binding"].write_text(json.dumps({
            "schema": "iam.keycloak.production-security/source-binding-v1",
            "current_version": input_record["current"]["version"],
            "current_source_commit": input_record["current"]["source_commit"],
            "candidate_version": input_record["candidate"]["version"],
            "candidate_source_commit": input_record["candidate"]["source_commit"],
            "name_status_sha256": guard.sha256(paths["source_name_status"]),
            "stat_sha256": guard.sha256(paths["source_stat"]),
        }), encoding="utf-8")
        paths["scan_binding"].write_text(json.dumps({
            "schema": "iam.keycloak.production-security/scan-binding-v1",
            "current_image": input_record["current"]["image"],
            "candidate_image": input_record["candidate"]["image"],
            "current_trivy_sha256": guard.sha256(paths["trivy"]),
            "candidate_trivy_sha256": guard.sha256(paths["candidate_trivy"]),
            "current_sbom_sha256": guard.sha256(paths["current_sbom"]),
            "candidate_sbom_sha256": guard.sha256(paths["candidate_sbom"]),
        }), encoding="utf-8")
        return guard.assess(SimpleNamespace(**paths))

    def test_patch_with_bidirectional_source_review_is_ready_for_rehearsal(self):
        result = self.assess(
            current_scan=self.trivy(self.input()["current"]["image"],
                                     {"VulnerabilityID": "CVE-old", "Severity": "CRITICAL", "FixedVersion": "26.0.5"}))
        self.assertEqual(result["state"], "READY_FOR_REHEARSAL")
        self.assertEqual(result["change_class"], "patch")
        self.assertEqual(result["current_vulnerabilities"]["CRITICAL"], 1)
        self.assertEqual(result["candidate_vulnerabilities"]["CRITICAL"], 0)

    def test_candidate_critical_or_fixable_high_holds(self):
        for finding in (
            {"VulnerabilityID": "CVE-critical", "Severity": "CRITICAL", "FixedVersion": ""},
            {"VulnerabilityID": "CVE-high", "Severity": "HIGH", "FixedVersion": "26.0.6"},
        ):
            with self.subTest(finding=finding):
                result = self.assess(candidate_scan=self.trivy(self.input()["candidate"]["image"], finding))
                self.assertEqual(result["state"], "HOLD_FOR_SECURITY")
                self.assertEqual(result["candidate_blockers"][0]["id"], finding["VulnerabilityID"])

    def test_minor_major_and_downgrade_require_manual_migration(self):
        for candidate, expected in (("26.1.0", "minor"), ("27.0.0", "major"), ("25.0.6", "downgrade")):
            with self.subTest(candidate=candidate):
                record = self.input(candidate)
                review = self.review(candidate, "manual_migration")
                result = self.assess(record, review)
                self.assertEqual(result["state"], "MANUAL_MIGRATION_REQUIRED")
                self.assertEqual(result["change_class"], expected)

    def test_model_cannot_review_a_different_candidate(self):
        review = self.review()
        review["candidate_source_commit"] = "9" * 40
        with self.assertRaisesRegex(guard.Refused, "not bound"):
            self.assess(review=review)

    def test_scanner_report_must_name_the_exact_image(self):
        wrong = self.trivy("registry.example/keycloak/keycloak@" + OLD_DIGEST)
        with self.assertRaisesRegex(guard.Refused, "not bound"):
            self.assess(candidate_scan=wrong)

    def test_candidate_sbom_must_be_nonempty_cyclonedx(self):
        with self.assertRaisesRegex(guard.Refused, "no components"):
            self.assess(candidate_sbom={
                "bomFormat": "CycloneDX", "specVersion": "1.6", "components": [],
            })

    def test_source_diff_must_be_bound_to_both_exact_commits(self):
        original = guard.validate_source_binding
        try:
            def changed(record, current, candidate, name_status, stat):
                record["current_source_commit"] = "9" * 40
                return original(record, current, candidate, name_status, stat)
            guard.validate_source_binding = changed
            with self.assertRaisesRegex(guard.Refused, "not bound"):
                self.assess()
        finally:
            guard.validate_source_binding = original

    def test_input_refuses_undeclared_secret_or_moving_image(self):
        record = self.input()
        record["environment"]["database"]["password"] = "must-not-be-here"
        with self.assertRaisesRegex(guard.Refused, "fields differ"):
            guard.validate_input(record)
        record = self.input()
        record["candidate"]["image"] = "registry.example/keycloak/keycloak:latest"
        with self.assertRaisesRegex(guard.Refused, "immutable"):
            guard.validate_input(record)
        record = self.input()
        record["policy"]["automatic_patch_only"] = False
        with self.assertRaisesRegex(guard.Refused, "automatic_patch_only"):
            guard.validate_input(record)
        record = self.input()
        record["environment"]["customizations"][0]["source_revision"] = "main"
        with self.assertRaisesRegex(guard.Refused, "immutable"):
            guard.validate_input(record)

    def test_private_registry_port_is_supported_and_bounded(self):
        record = self.input()
        record["candidate"]["image"] = "registry.example:5000/iam/keycloak@" + NEW_DIGEST
        guard.validate_input(record)
        record["candidate"]["image"] = "registry.example:99999/iam/keycloak@" + NEW_DIGEST
        with self.assertRaisesRegex(guard.Refused, "immutable"):
            guard.validate_input(record)

    def test_same_version_with_different_identity_holds(self):
        record = self.input("26.0.4")
        review = self.review("26.0.4")
        result = self.assess(record, review)
        self.assertEqual(result["state"], "HOLD_FOR_SECURITY")
        self.assertTrue(result["identity_drift"])

    def test_source_coverage_and_both_risk_directions_are_required(self):
        for key, value in (("coverage", ["scanner only"]), ("risk_of_staying", []), ("risk_of_upgrading", [])):
            review = self.review()
            review[key] = value
            with self.subTest(key=key), self.assertRaises(guard.Refused):
                self.assess(review=review)

    def test_readiness_refuses_self_asserted_rehearsal(self):
        self.assess()
        with self.assertRaisesRegex(guard.Refused, "readiness is disabled"):
            guard.readiness(SimpleNamespace(assessment=self.root / "assessment.json"))

    def test_classification_is_deterministic(self):
        self.assertEqual(guard.change_class("26.0.4", "26.0.5"), "patch")
        self.assertEqual(guard.change_class("26.0.4", "26.1.0"), "minor")
        self.assertEqual(guard.change_class("26.0.4", "27.0.0"), "major")
        self.assertEqual(guard.change_class("26.0.4", "26.0.4"), "current")
        self.assertEqual(guard.change_class("26.0.4", "25.0.9"), "downgrade")

    def test_review_schema_and_guard_require_the_same_top_level_fields(self):
        schema = json.loads((SKILL / "assets/review-schema.json").read_text(encoding="utf-8"))
        self.assertEqual(set(schema["required"]), set(self.review()))
        self.assertFalse(schema["additionalProperties"])

    def test_composite_action_is_an_offline_evidence_gate(self):
        action = (SKILL / "action.yml").read_text(encoding="utf-8")
        self.assertIn("scripts/keycloak_guard.py\" assess", action)
        for forbidden in ("codex exec", "curl ", "wget ", "ssh ", "kubectl ", "terraform "):
            self.assertNotIn(forbidden, action)

    def test_model_and_artifact_workflow_is_not_distributed(self):
        self.assertFalse((SKILL / "assets/github-assessment.yml").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
