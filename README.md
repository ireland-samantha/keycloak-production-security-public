<!-- AI-assisted public release review via Codex, 2026-10-26. -->
# Keycloak Production Security — public evaluation

Offline evidence consistency checks and an advisory review procedure for Keycloak upgrade planning.
Version 0.1.1 is experimental and intended for controlled evaluation with synthetic or sanitized inputs.

The Python tool checks selected fields, hashes, and decision rules in supplied inventory, scanner reports,
SBOMs, source-diff records, and a structured review. It does not independently establish that evidence is true,
complete, fresh, authentic, or produced by the claimed scanner. A matching hash is a consistency check.

## Included

| Component | Purpose |
|---|---|
| [SKILL.md](SKILL.md) | Advisory assessment procedure |
| [action.yml](action.yml) | Offline composite action for trusted local evidence |
| [scripts/keycloak_guard.py](scripts/keycloak_guard.py) | Format, identity, hash, and selected policy checks |
| [assets/input-schema.json](assets/input-schema.json) | Inventory shape |
| [assets/review-schema.json](assets/review-schema.json) | Structured review shape |
| [references/inventory-adapter.md](references/inventory-adapter.md) | Synthetic inventory example and adapter requirements |
| [references/deployment-contract.md](references/deployment-contract.md) | Requirements for a separately implemented production adapter |
| [RELEASE-REVIEW.md](RELEASE-REVIEW.md) | Release risk model, mitigations, and limits |

There is no production adapter, hosted service, automatic upgrade, or bundled model/network integration.
The earlier self-hosted assessment template is excluded because source archives and artifact uploads need a
separately verified confidentiality boundary. Public CI uses only repository files and synthetic tests.

## Evaluate locally

Check the license section before using or redistributing the package. In an authorized local copy:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_keycloak_guard.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_public_release.py
python3 scripts/release_check.py
```

Python 3.11 or later and the standard library are sufficient for these commands.
The offline CLI prints assessment content to stdout; redirect it into an access-controlled local file.
Do not put real inventory, scanner output, SBOMs, model output, credentials, or customer source in public
issues, public CI logs, public artifacts, or this repository. Unknown fields are rejected, but accepted free-text
fields can still contain sensitive information. Review and sanitize inputs before processing.

## Interpret states carefully

- `NO_CHANGE`: the supplied current and candidate identities match and selected policy checks did not hold.
- `READY_FOR_REHEARSAL`: an advisory patch-candidate result; independent validation and authorization are still required.
- `MANUAL_MIGRATION_REQUIRED`: the selected version transition or review needs manual planning.
- `HOLD_FOR_SECURITY`: a selected policy condition, review uncertainty, or missing prerequisite prevents progression.

Malformed or mismatched evidence exits with `REFUSED` and code 2. A well-formed assessment, including
`HOLD_FOR_SECURITY`, exits with code 0; automation must inspect the state. The legacy `readiness` command
always refuses. Caller-written booleans and digest strings cannot establish an independent rehearsal.
Every assessment includes `advisory_only: true` and `authorizes_deployment: false`.
No output authorizes a production change or certifies security, compatibility, recovery, or regulatory compliance.
Unit tests cover synthetic cases; no real Keycloak deployment or recovery was verified for this release.

Use current [Keycloak documentation](https://www.keycloak.org/documentation) and the
[production guide](https://www.keycloak.org/server/configuration-production) for environment-specific work.
Keycloak and OpenAI product names identify interoperability targets; no affiliation or endorsement is claimed.

See [SECURITY.md](SECURITY.md) for private reporting and [CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes.

## License

This repository is intentionally unlicensed. No open-source license or other permission grant is provided at this
time. The absence of a license means use, copying, modification, and redistribution require permission from the
repository owner except where applicable law or GitHub's Terms of Service provide otherwise.
