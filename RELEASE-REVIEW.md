<!-- AI-assisted public release review via Codex, 2026-10-26. -->
# Public release review — 0.1.1

Review date: 2026-10-26. Scope: every file in the package manifest, nested assets/references/workflows,
and publication metadata. The distribution is a fresh snapshot. Private Git history, annotated tags,
issues, discussion, logs, artifacts, and external customer repositories are excluded.

## Method and release threshold

This review adapts the threat-event, likelihood, impact, uncertainty, and residual-risk approach in
[NIST SP 800-30 Rev. 1](https://csrc.nist.gov/pubs/sp/800/30/r1/final).
It is a project-specific release screen, not a NIST assessment or certification.

For each event, identify the exposed asset, evidence, plausible failure, existing controls, remediation,
and remaining uncertainty. Likelihood is 1 (unlikely), 2 (possible but constrained), 3 (plausible),
4 (likely in ordinary use), or 5 (expected). Impact is 1 (minor), 2 (limited), 3 (material rework or dispute),
4 (serious financial/reputational harm), or 5 (credential, confidential data, or irreversible production harm).
The product L×I is an ordinal prioritization aid: 1–4 low, 5–9 moderate, 10–15 high, 16–25 critical.
These scores are judgment, not measured probabilities or expected monetary loss.

Block publication for any residual score of 10 or more, an observed secret or confidential data item,
unresolved evidence of third-party ownership restrictions, or a public claim contradicted by observed behavior.
Do not average away a blocker. Resolve it, remove the affected component, then repeat review of all changed bytes
and their references. Re-run the entire content check and tests before constructing the publication commit.
Moderate residuals require an explicit scope limit and documented reason for release.

## Findings and residuals

| Threat event / asset | Evidence and mitigation | Before L×I | After L×I | Confidence / remaining boundary |
|---|---|---:|---:|---|
| Confidential source or credential publication | Full text review; exact file allowlist; credential, email, address, binary, symlink, and private-file checks; fresh history | 2×5=10 | 1×5=5 | Medium: pattern checks cannot discover all secrets or decide IP ownership; no sensitive item observed in reviewed files |
| Customer IP reaches model/provider or public artifacts | Self-hosted assessment archive/model/upload template excluded; no model/network call in the offline action | 4×5=20 | 1×5=5 | High for removal; customer-created future integrations need their own data-flow review |
| Self-asserted rehearsal mistaken for approval | `readiness` unconditionally refuses, including fabricated or missing input; no production adapter bundled | 4×5=20 | 1×5=5 | High for tested refusal; external consumers must not treat assessment state as authority |
| Reputation or reliance dispute from broad assurance claims | README, skill, guide, action description, and changelog state actual checks and unverified behavior; unknowns/high risk hold | 4×4=16 | 2×3=6 | Medium: users can still misuse or misunderstand advisory results |
| Ambiguous JSON or dangling output symlink changes meaning/target | Duplicate keys refuse recursively; dangling output symlinks refuse; focused regressions | 3×3=9 | 1×3=3 | High for tested cases; concurrent local attackers and ancestor-link races remain outside the trusted-directory model |
| Supply-chain or CI execution leaks privileged data | Only hosted synthetic-test CI; read-only permissions; checkout pinned by full commit; no persisted checkout credentials or artifact upload | 3×4=12 | 1×4=4 | Medium: hosting/runner supply chain remains external; dependency monitoring is retained |
| Copyright, endorsement, or commercial-term confusion | Existing no-license position preserved; synthetic provenance retained; no copied upstream code, customer contracts, or promised service tiers bundled | 3×3=9 | 1×3=3 | Medium: source review is not ownership verification or a legal opinion; permission is needed for reuse under the existing terms |
| Old history or metadata re-enters public distribution | New repository, fresh single root commit, no inherited tags/branches; verify remote tree, ancestry, and author metadata | 3×5=15 | 2×3=6 | Publication uses the GitHub account’s configured author email; this is not an anonymous release. Copies elsewhere cannot be erased |

An independent local instruction test reproduced an uncertainty hold and disabled-readiness refusal.
It also confirmed that a coverage string alone is not proof of an adequate source review: the v1 guard
cannot recognize undisclosed uncertainty. Every assessment explicitly denies deployment authority.

The moderate residuals are retained because the release is explicitly an experimental, offline, advisory package.
They do not justify publishing observed confidential material or using the tool as a production approval system.
The repository owner authorized preparation and publication; that does not establish a legal guarantee.
The GitHub publishing connector does not expose an author-email override. Its initialization and publication
commit use the configured account identity; the intended noreply author could not be applied through that tool.
Private source commit/tag metadata are excluded, but the publication email remains visible in Git metadata.

## Verification and evidence limits

- Inspect all source text, including schemas, fixtures, hidden repository configuration, nested templates, and links.
- Use only synthetic fixtures for executable tests. Test candidate substitution, policy holds, malformed evidence,
  disabled readiness, ambiguous JSON, output symlink refusal, and absence of the hosted model/upload template.
- Run `scripts/release_check.py` against the exact manifest. It checks content patterns, the file set, and hashes;
  it is a narrow release screen, not a general-purpose secret scanner or IP classifier.
- Retain byte hashes in `PACKAGE-MANIFEST.sha256`; it detects changes against the committed manifest, not a malicious
  change to both manifest and files. Verify the publication commit independently before relying on it.
- After publication, compare the remote tree and every file identity with the reviewed package; confirm one root
  commit and no inherited refs. A passing CI result is scoped to synthetic tests and package checks.

No deployed Keycloak instance, production database, restore procedure, cloud account, AI-provider integration,
customer source repository, or legal contract was assessed. Scanner claims, SBOM completeness, source provenance,
evidence freshness, rehearsal authenticity, and approval signatures are not established by the v1 CLI.
No legal opinion, security certification, production readiness, or absence-of-vulnerabilities conclusion is made.

## Future release rule

Reassess new inputs, dependencies, claims, and outbound data paths. Keep real evidence outside this repository.
Use private vulnerability reporting. For an actual credential exposure, revoke/rotate the credential first and follow
[GitHub's sensitive-data removal guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).
A new repository or force push does not erase existing clones, forks, caches, or prior disclosures.
