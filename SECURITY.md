<!-- Synthetic origin: OpenAI, GPT-6.1, via Codex. A human did not make this change directly, a system did. -->
# Security policy

## Supported version

Security fixes are currently made against the latest repository state. Until a later support matrix is published,
older tags should be treated as unsupported.

## Report a vulnerability

Do not open a public issue for a suspected vulnerability, credential exposure, authentication bypass, unsafe
deployment behavior, or evidence-integrity failure.

Use this repository's Security tab and **Report a vulnerability** for private reporting. If that option is
unavailable, do not post sensitive details publicly; request a private reporting channel from the maintainer. Include:

- affected commit or version;
- the exact entry point and trust boundary;
- realistic prerequisites and impact;
- reproduction or source trace;
- any proposed mitigation; and
- whether disclosure is time-sensitive.

Do not include production credentials, tokens, personal data, database exports, signing material, or customer-private
source. Use synthetic fixtures and redact infrastructure identifiers.

## Scope priorities

High-priority reports include:

- model output bypassing a deterministic gate;
- stale or substituted source, image, SBOM, scanner, assessment, or rehearsal evidence;
- command or path injection through inventory or action inputs;
- exposure of runner, registry, cloud, database, or Codex authentication material;
- unsafe mixed-version, schema-migration, rollback, or production-promotion behavior; and
- cross-realm, cross-tenant, authentication, authorization, or signing-key boundary failures.

## Safe research

Use disposable infrastructure and nonproduction data. Do not test against systems you do not own or lack permission
to assess. A report does not grant authority to access a customer environment or perform a production deployment.
