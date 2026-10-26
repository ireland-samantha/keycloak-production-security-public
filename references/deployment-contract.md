<!-- Synthetic origin: OpenAI, GPT-6.1, via Codex. A human did not make this change directly, a system did. -->
# Production deployment adapter requirements

These are design requirements, not implemented controls or evidence of a verified production integration.
The public package performs assessment only, and `readiness` always refuses.

The portable skill never embeds a vendor-specific root command. An IAM team supplies a reviewed adapter that implements
these operations against fixed targets. Every operation consumes one immutable candidate binding and emits JSON.

## Required operations

| Operation | Effects | Required output |
|---|---|---|
| 'inventory' | read-only | runtime version, image/platform digest, database engine/version, topology, provider/theme inventory |
| 'plan' | read-only | exact current/candidate, expected schema work, traffic plan, recovery target, drift/refusals |
| 'prepare-canary' | disposable only | clone identity, isolation proof, candidate identity, cleanup handle |
| 'run-canary' | clone or explicitly supported synthetic traffic only | journeys, failures, resource/startup observations |
| 'rollback-canary' | disposable cleanup | removal/readback evidence |
| 'promote' | production mutation | old/new slots, traffic state, database state, rollback handle |
| 'stabilize' | bounded production observation | samples, duration, journeys, rollback/finalization disposition |
| 'rollback' | production mutation | restored slot/database, journeys, data-loss window, unresolved state |
| 'finalize' | retires recovery only after approval | retained evidence, backup expiry, old-slot disposition |

The adapter must reject arbitrary targets, moving tags, shell fragments, unknown candidate fields, stale approvals,
concurrent runs, and state drift. It must lock the target before mutation and bind state files to the target and
candidate. Its production identity must be short-lived and least privilege.

## Red/blue and database safety

A safe default is blue serving production while red runs against an isolated clone. This is a compatibility canary, not
a percentage production rollout. Routing real users to red is allowed only if old and new Keycloak versions may
concurrently use the same database/session/cache format, upstream supports that exact pair, and the team has observed it
under production-shaped load.

Before promotion, prove database restore. After promotion, keep blue and the recovery snapshot until the stability gate
and owner finalization. If candidate startup migrated the database and downgrade is unproved, restarting blue is not a
rollback. State whether recovery is snapshot restore or forward-fix and state the recovery point/data-loss window.

## Control loss and stability

Run the post-promotion monitor on the target side or under a durable controller. A dropped CI/SSH session must not leave
an unobserved half-promotion. The monitor checks issuer metadata, signing keys, authentication journeys, refresh/logout,
custom providers, readiness, error/restart rates, latency, and resource bounds for the policy duration.

A failed probe triggers the pre-authorized recovery path only while its exact recovery conditions still hold. Ambiguous
state stops automatic retries and reports manual recovery. Finalization is a separate explicit operation.
