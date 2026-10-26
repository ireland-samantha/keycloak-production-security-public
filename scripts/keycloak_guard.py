#!/usr/bin/env python3
# Synthetic origin: OpenAI, GPT-6.1, via Codex. A human did not make this change directly, a system did.
"""Deterministic evidence gates for the Keycloak production security skill."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

VERSION = re.compile(r"^[1-9][0-9]*\.[0-9]+\.[0-9]+$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE = re.compile(
    r"^(?P<registry>[a-z0-9.-]+)(?::(?P<port>[1-9][0-9]{0,4}))?"
    r"(?:/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}$"
)
CUSTOM_REVISION = re.compile(r"^(?:(?:commit|git):[0-9a-f]{40}|sha256:[0-9a-f]{64})$")
RISKS = {"info", "low", "medium", "high", "critical"}
CONFIDENCE = {"low", "medium", "high"}
CHECKS = {
    "database_clone", "backup_restore", "blue_baseline", "candidate_migration",
    "customizations", "journeys", "rollback", "canary", "cleanup",
}


class Refused(ValueError):
    """Evidence is malformed, mismatched, or insufficient for the next stage."""


def exact(record, keys, label):
    if not isinstance(record, dict):
        raise Refused(f"{label} must be an object")
    difference = set(record) ^ set(keys)
    if difference:
        raise Refused(f"{label} fields differ from contract: {sorted(difference)}")
    return record


def nonempty(value, label):
    if not isinstance(value, str) or not value.strip():
        raise Refused(f"{label} must be nonempty text")
    return value


def string_list(value, label, required=False):
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise Refused(f"{label} must be an array of nonempty strings")
    if required and not value:
        raise Refused(f"{label} must not be empty")
    return value


def unique_object(pairs):
    record = {}
    for key, value in pairs:
        if key in record:
            raise Refused("duplicate JSON object key")
        record[key] = value
    return record


def load(path: Path, maximum=32 * 1024 * 1024):
    if path.is_symlink() or not path.is_file():
        raise Refused(f"evidence is not a regular file: {path}")
    if path.stat().st_size > maximum:
        raise Refused(f"evidence exceeds {maximum} bytes: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Refused(f"invalid JSON evidence {path}: {error}") from error


def sha256(path: Path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def semver(value, label):
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        raise Refused(f"{label} is not a normalized Keycloak version")
    return tuple(int(part) for part in value.split("."))


def change_class(current, candidate):
    old, new = semver(current, "current.version"), semver(candidate, "candidate.version")
    if new < old:
        return "downgrade"
    if new == old:
        return "current"
    if new[:2] == old[:2]:
        return "patch"
    if new[0] == old[0]:
        return "minor"
    return "major"


def release(value, label):
    value = exact(value, {"version", "source_commit", "upstream_image", "upstream_platform_digest",
                         "image", "platform_digest"}, label)
    semver(value["version"], label + ".version")
    if not isinstance(value["source_commit"], str) or not COMMIT.fullmatch(value["source_commit"]):
        raise Refused(f"{label}.source_commit must be a full lowercase commit")
    for key in ("upstream_image", "image"):
        match = IMAGE.fullmatch(value[key]) if isinstance(value[key], str) else None
        if not match or (match["port"] and int(match["port"]) > 65535):
            raise Refused(f"{label}.{key} must be an immutable image reference")
    for key in ("upstream_platform_digest", "platform_digest"):
        if not isinstance(value[key], str) or not DIGEST.fullmatch(value[key]):
            raise Refused(f"{label}.{key} must be an immutable digest")
    return value


def validate_input(record):
    record = exact(record, {"schema", "current", "candidate", "environment", "policy"}, "input")
    if record["schema"] != "iam.keycloak.production-security/input-v1":
        raise Refused("unknown input schema")
    current, candidate = release(record["current"], "current"), release(record["candidate"], "candidate")
    environment = exact(record["environment"], {"database", "topology", "customizations", "journeys"}, "environment")
    database = exact(environment["database"], {"engine", "version", "clone_available", "restore_tested"},
                     "environment.database")
    nonempty(database["engine"], "environment.database.engine")
    nonempty(database["version"], "environment.database.version")
    if not all(isinstance(database[key], bool) for key in ("clone_available", "restore_tested")):
        raise Refused("database clone/restore fields must be booleans")
    topology = exact(environment["topology"], {"nodes", "cache_mode", "mixed_version_supported"},
                     "environment.topology")
    if not isinstance(topology["nodes"], int) or isinstance(topology["nodes"], bool) or topology["nodes"] < 1:
        raise Refused("environment.topology.nodes must be a positive integer")
    nonempty(topology["cache_mode"], "environment.topology.cache_mode")
    if not isinstance(topology["mixed_version_supported"], bool):
        raise Refused("environment.topology.mixed_version_supported must be boolean")
    if not isinstance(environment["customizations"], list):
        raise Refused("environment.customizations must be an array")
    for index, item in enumerate(environment["customizations"]):
        item = exact(item, {"name", "kind", "source_revision", "compatibility_test"},
                     f"environment.customizations[{index}]")
        for key in ("name", "source_revision", "compatibility_test"):
            nonempty(item[key], f"environment.customizations[{index}].{key}")
        if not CUSTOM_REVISION.fullmatch(item["source_revision"]):
            raise Refused(f"environment.customizations[{index}].source_revision must be immutable")
        if item["kind"] not in {"provider", "theme", "extension", "script", "other"}:
            raise Refused(f"environment.customizations[{index}].kind is unknown")
    string_list(environment["journeys"], "environment.journeys", required=True)
    policy = exact(record["policy"], {"block_critical", "block_fixable_high", "automatic_patch_only",
                   "minimum_stability_seconds", "rpo_seconds", "rto_seconds"}, "policy")
    for key in ("block_critical", "block_fixable_high", "automatic_patch_only"):
        if not isinstance(policy[key], bool):
            raise Refused(f"policy.{key} must be boolean")
    if policy["automatic_patch_only"] is not True:
        raise Refused("input-v1 requires automatic_patch_only=true")
    for key in ("minimum_stability_seconds", "rpo_seconds", "rto_seconds"):
        if not isinstance(policy[key], int) or isinstance(policy[key], bool) or policy[key] < 0:
            raise Refused(f"policy.{key} must be a nonnegative integer")
    if not 60 <= policy["minimum_stability_seconds"] <= 86400:
        raise Refused("policy.minimum_stability_seconds must be between 60 and 86400")
    return record, current, candidate, environment, policy


def validate_risks(items, label):
    if not isinstance(items, list) or not items:
        raise Refused(f"{label} must be a nonempty array")
    for index, item in enumerate(items):
        item = exact(item, {"id", "severity", "evidence", "impact", "recommendation", "confidence"},
                     f"{label}[{index}]")
        for key in ("id", "evidence", "impact", "recommendation"):
            nonempty(item[key], f"{label}[{index}].{key}")
        if item["severity"] not in RISKS or item["confidence"] not in CONFIDENCE:
            raise Refused(f"{label}[{index}] has an unknown severity or confidence")


def validate_review(record, current, candidate):
    keys = {
        "schema", "current_version", "current_source_commit", "current_image_digest",
        "current_platform_digest", "candidate_version", "candidate_source_commit",
        "candidate_image_digest", "candidate_platform_digest", "decision", "overall_risk", "summary", "risk_of_staying",
        "risk_of_upgrading", "breaking_changes", "blockers", "coverage", "unknowns",
        "migration_steps", "rollback_steps", "canary_checks",
    }
    record = exact(record, keys, "review")
    if record["schema"] != "iam.keycloak.production-security/review-v1":
        raise Refused("unknown review schema")
    binding = (
        record["current_version"], record["current_source_commit"], record["current_image_digest"],
        record["current_platform_digest"], record["candidate_version"],
        record["candidate_source_commit"], record["candidate_image_digest"],
        record["candidate_platform_digest"],
    )
    expected = (
        current["version"], current["source_commit"], current["image"].rsplit("@", 1)[1],
        current["platform_digest"], candidate["version"], candidate["source_commit"],
        candidate["image"].rsplit("@", 1)[1], candidate["platform_digest"],
    )
    if binding != expected:
        raise Refused("review is not bound to the exact input candidate")
    if record["decision"] not in {"approve_rehearsal", "manual_migration", "hold"}:
        raise Refused("review decision is unknown")
    if record["overall_risk"] not in {"low", "medium", "high", "critical"}:
        raise Refused("review overall_risk is unknown")
    nonempty(record["summary"], "review.summary")
    validate_risks(record["risk_of_staying"], "review.risk_of_staying")
    validate_risks(record["risk_of_upgrading"], "review.risk_of_upgrading")
    if not isinstance(record["breaking_changes"], list):
        raise Refused("review.breaking_changes must be an array")
    for index, item in enumerate(record["breaking_changes"]):
        item = exact(item, {"area", "evidence", "impact", "compatibility_test"},
                     f"review.breaking_changes[{index}]")
        for key in item:
            nonempty(item[key], f"review.breaking_changes[{index}].{key}")
    for key in ("blockers", "unknowns"):
        string_list(record[key], "review." + key)
    for key in ("coverage", "migration_steps", "rollback_steps", "canary_checks"):
        string_list(record[key], "review." + key, required=True)
    if not any("source" in entry.lower() or "/" in entry for entry in record["coverage"]):
        raise Refused("review.coverage does not identify source coverage")
    return record


def trivy_summary(record, label, expected_image):
    if not isinstance(record, dict) or not isinstance(record.get("SchemaVersion"), int):
        raise Refused(f"{label} has no scanner schema version")
    if record.get("ArtifactName") != expected_image:
        raise Refused(f"{label} is not bound to {expected_image}")
    if not isinstance(record.get("Results"), list) or not record["Results"]:
        raise Refused(f"{label} has no Trivy Results")
    counts = {severity: 0 for severity in ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")}
    findings = []
    for result in record["Results"]:
        if not isinstance(result, dict) or not isinstance(result.get("Vulnerabilities") or [], list):
            raise Refused(f"{label} contains a malformed result")
        for item in result.get("Vulnerabilities") or []:
            if not isinstance(item, dict):
                raise Refused(f"{label} contains a malformed vulnerability")
            severity = str(item.get("Severity") or "UNKNOWN").upper()
            severity = severity if severity in counts else "UNKNOWN"
            counts[severity] += 1
            findings.append({
                "id": str(item.get("VulnerabilityID") or "unknown"),
                "severity": severity,
                "fixed": bool(str(item.get("FixedVersion") or "").strip()),
            })
    return {"counts": counts, "findings": findings}


def validate_sbom(record, label):
    if not isinstance(record, dict) or record.get("bomFormat") != "CycloneDX":
        raise Refused(f"{label} is not a CycloneDX SBOM")
    if not isinstance(record.get("specVersion"), str) or not record["specVersion"].strip():
        raise Refused(f"{label} has no specification version")
    if not isinstance(record.get("components"), list) or not record["components"]:
        raise Refused(f"{label} has no components")


def validate_scan_binding(record, current, candidate, args):
    record = exact(record, {
        "schema", "current_image", "candidate_image", "current_trivy_sha256",
        "candidate_trivy_sha256", "current_sbom_sha256", "candidate_sbom_sha256",
    }, "scan binding")
    if record["schema"] != "iam.keycloak.production-security/scan-binding-v1":
        raise Refused("unknown scan binding schema")
    expected = (
        current["image"], candidate["image"], sha256(args.trivy), sha256(args.candidate_trivy),
        sha256(args.current_sbom), sha256(args.candidate_sbom),
    )
    observed = (
        record["current_image"], record["candidate_image"], record["current_trivy_sha256"],
        record["candidate_trivy_sha256"], record["current_sbom_sha256"],
        record["candidate_sbom_sha256"],
    )
    if observed != expected:
        raise Refused("scanner evidence is not bound to the exact input images")
    return record


def source_evidence(path, label):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
        raise Refused(f"{label} is not a bounded regular file")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeError as error:
        raise Refused(f"{label} is not UTF-8 text") from error
    if "\x00" in text:
        raise Refused(f"{label} contains a NUL byte")
    return text


def validate_source_binding(record, current, candidate, name_status, stat):
    record = exact(record, {
        "schema", "current_version", "current_source_commit", "candidate_version",
        "candidate_source_commit", "name_status_sha256", "stat_sha256",
    }, "source binding")
    if record["schema"] != "iam.keycloak.production-security/source-binding-v1":
        raise Refused("unknown source binding schema")
    expected = (
        current["version"], current["source_commit"], candidate["version"],
        candidate["source_commit"], sha256(name_status), sha256(stat),
    )
    observed = (
        record["current_version"], record["current_source_commit"], record["candidate_version"],
        record["candidate_source_commit"], record["name_status_sha256"], record["stat_sha256"],
    )
    if observed != expected:
        raise Refused("source diff is not bound to the exact input commits")
    return record


def outputs(path, values):
    if not path:
        return
    with path.open("a", encoding="utf-8") as stream:
        for key, value in values.items():
            text = str(value)
            if "\n" in text or "\r" in text:
                raise Refused(f"output {key} is multiline")
            stream.write(f"{key}={text}\n")


def write_json(path, value):
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise Refused(f"output parent is not a regular directory: {path.parent}")
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise Refused(f"output is not a regular file: {path}")
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def assess(args):
    input_record, current, candidate, environment, policy = validate_input(load(args.input, 1024 * 1024))
    review = validate_review(load(args.review, 2 * 1024 * 1024), current, candidate)
    current_scan = trivy_summary(load(args.trivy), "current Trivy report", current["image"])
    candidate_scan = trivy_summary(load(args.candidate_trivy), "candidate Trivy report", candidate["image"])
    validate_sbom(load(args.current_sbom), "current image SBOM")
    validate_sbom(load(args.candidate_sbom), "candidate image SBOM")
    scan_binding = validate_scan_binding(
        load(args.scan_binding, 64 * 1024), current, candidate, args,
    )
    names = source_evidence(args.source_name_status, "source name/status diff")
    stats = source_evidence(args.source_stat, "source diff stat")
    source_binding = validate_source_binding(
        load(args.source_binding, 64 * 1024), current, candidate,
        args.source_name_status, args.source_stat,
    )
    if current["source_commit"] != candidate["source_commit"] and not names.strip() and not stats.strip():
        raise Refused("changed source commits have no source diff evidence")
    candidate_blockers = [
        item for item in candidate_scan["findings"]
        if (policy["block_critical"] and item["severity"] == "CRITICAL")
        or (policy["block_fixable_high"] and item["severity"] == "HIGH" and item["fixed"])
    ]
    kind = change_class(current["version"], candidate["version"])
    identity_drift = kind == "current" and current != candidate
    if (candidate_blockers or review["decision"] == "hold" or review["blockers"]
            or review["overall_risk"] in {"high", "critical"} or review["unknowns"]
            or not environment["database"]["clone_available"]
            or not environment["database"]["restore_tested"]):
        state = "HOLD_FOR_SECURITY"
    elif identity_drift:
        state = "HOLD_FOR_SECURITY"
    elif kind in {"minor", "major", "downgrade"} or review["decision"] == "manual_migration":
        state = "MANUAL_MIGRATION_REQUIRED"
    elif kind == "current":
        state = "NO_CHANGE"
    elif kind == "patch" and review["decision"] == "approve_rehearsal":
        state = "READY_FOR_REHEARSAL"
    else:
        state = "HOLD_FOR_SECURITY"
    assessment = {
        "schema": "iam.keycloak.production-security/assessment-v1",
        "advisory_only": True,
        "authorizes_deployment": False,
        "state": state,
        "change_class": kind,
        "identity_drift": identity_drift,
        "binding": candidate,
        "current": current,
        "candidate_blockers": candidate_blockers,
        "current_vulnerabilities": current_scan["counts"],
        "candidate_vulnerabilities": candidate_scan["counts"],
        "review": review,
        "scan_binding": scan_binding,
        "source_binding": source_binding,
        "rehearsal_prerequisites": {
            "database_clone": environment["database"]["clone_available"],
            "restore_tested": environment["database"]["restore_tested"],
        },
        "evidence_sha256": {
            "input": sha256(args.input), "current_trivy": sha256(args.trivy),
            "candidate_trivy": sha256(args.candidate_trivy), "review": sha256(args.review),
            "current_sbom": sha256(args.current_sbom), "candidate_sbom": sha256(args.candidate_sbom),
            "scan_binding": sha256(args.scan_binding),
            "source_binding": sha256(args.source_binding),
            "source_name_status": sha256(args.source_name_status), "source_stat": sha256(args.source_stat),
        },
    }
    write_json(args.output, assessment)
    outputs(args.github_output, {"state": state, "change_class": kind,
                                "assessment_sha256": sha256(args.output)})
    return assessment


def readiness(args):
    raise Refused("readiness is disabled: independently verified rehearsal and approval are not implemented")


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    classify = commands.add_parser("classify")
    classify.add_argument("--current", required=True)
    classify.add_argument("--candidate", required=True)
    validate = commands.add_parser("validate-input")
    validate.add_argument("--input", type=Path, required=True)
    assessment = commands.add_parser("assess")
    assessment.add_argument("--input", type=Path, required=True)
    assessment.add_argument("--trivy", type=Path, required=True)
    assessment.add_argument("--candidate-trivy", type=Path, required=True)
    assessment.add_argument("--current-sbom", type=Path, required=True)
    assessment.add_argument("--candidate-sbom", type=Path, required=True)
    assessment.add_argument("--scan-binding", type=Path, required=True)
    assessment.add_argument("--review", type=Path, required=True)
    assessment.add_argument("--source-binding", type=Path, required=True)
    assessment.add_argument("--source-name-status", type=Path, required=True)
    assessment.add_argument("--source-stat", type=Path, required=True)
    assessment.add_argument("--output", type=Path, required=True)
    assessment.add_argument("--github-output", type=Path)
    ready = commands.add_parser("readiness", help="disabled; always refuses and cannot issue approval")
    ready.add_argument("--assessment", type=Path, required=True)
    ready.add_argument("--rehearsal", type=Path, required=True)
    ready.add_argument("--output", type=Path, required=True)
    ready.add_argument("--github-output", type=Path)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "classify":
            print(change_class(args.current, args.candidate))
        elif args.command == "validate-input":
            record, _, _, _, _ = validate_input(load(args.input, 1024 * 1024))
            print(json.dumps(record, sort_keys=True))
        elif args.command == "assess":
            print(json.dumps(assess(args), sort_keys=True))
        else:
            print(json.dumps(readiness(args), sort_keys=True))
        return 0
    except Refused as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
