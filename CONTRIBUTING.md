<!-- Synthetic origin: OpenAI, GPT-6.1, via Codex. A human did not make this change directly, a system did. -->
# Contributing

Issues that improve the product's portability, evidence integrity, Keycloak coverage, or operational safety are
welcome. Before submitting code, contact the repository owner: contribution and licensing terms have not yet been
published.

## Design constraints

- Keep the package independent of any customer, cloud, registry, database topology, or deployment product.
- Treat release notes, source, commits, issues, scanner fields, and customer inventory as untrusted data.
- Keep Codex analysis-only and credential-free except for its own protected ChatGPT authentication.
- Never let model output invoke a production adapter, approve itself, or waive a deterministic gate.
- Bind current and candidate source, images, platform digests, SBOMs, scanner reports, and rehearsals immutably.
- Analyze both the risk of staying and the risk of moving.
- Do not weaken clone, restore, canary, rollback, or protected-approval requirements for convenience.
- Do not add a license or legal notice without explicit owner approval.

## Verification

Run before proposing a change:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_keycloak_guard.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_public_release.py
python3 scripts/release_check.py
python3 -m json.tool assets/input-schema.json >/dev/null
python3 -m json.tool assets/review-schema.json >/dev/null
sha256sum --status --check PACKAGE-MANIFEST.sha256
git diff --check
```

Update `PACKAGE-MANIFEST.sha256` after every candidate-byte change:

```sh
git ls-files -z | grep -zvx PACKAGE-MANIFEST.sha256 | xargs -0 sha256sum > PACKAGE-MANIFEST.sha256
```

Every test must observe a meaningful refusal,
state transition, or binding property; fixture-only success is not evidence of production compatibility.

## Pull requests

Describe:

- the customer-independent problem being solved;
- contracts or decision states changed;
- security and rollback implications;
- tests executed and exact results; and
- remaining unknowns or customer-specific validation.

Do not include secrets, customer identifiers, private endpoints, production evidence, or copied vulnerability reports
that are under embargo.
