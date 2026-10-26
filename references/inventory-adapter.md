<!-- Synthetic origin: OpenAI, GPT-6.1, via Codex. A human did not make this change directly, a system did. -->
# Assessment inventory adapter

An integration may supply a separately reviewed read-only inventory adapter. No hosted workflow or adapter
is bundled. The adapter should obtain independently observed current and candidate identities and emit an `input-v1`
record into a private evidence directory. The Python validator checks selected fields, not the adapter's honesty.

The adapter must obtain the current version, source mapping, image manifest digest, and platform digest from authoritative
runtime or release records. It must not copy the candidate values into the current fields. If a current source commit
cannot be established, stop rather than substitute a branch or local checkout.

Synthetic example shape (placeholder versions and hashes, not deployment recommendations):

~~~json
{
  "schema": "iam.keycloak.production-security/input-v1",
  "current": {
    "version": "26.0.4",
    "source_commit": "1111111111111111111111111111111111111111",
    "upstream_image": "quay.io/keycloak/keycloak@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "upstream_platform_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "image": "registry.example/iam/keycloak@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "platform_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "candidate": {
    "version": "26.0.5",
    "source_commit": "2222222222222222222222222222222222222222",
    "upstream_image": "quay.io/keycloak/keycloak@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "upstream_platform_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "image": "registry.example/iam/keycloak@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "platform_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  },
  "environment": {
    "database": {
      "engine": "postgresql",
      "version": "16",
      "clone_available": true,
      "restore_tested": true
    },
    "topology": {
      "nodes": 2,
      "cache_mode": "distributed",
      "mixed_version_supported": false
    },
    "customizations": [
      {
        "name": "tenant-policy",
        "kind": "provider",
        "source_revision": "commit:3333333333333333333333333333333333333333",
        "compatibility_test": "compile against candidate and exercise tenant login/refusal journeys"
      }
    ],
    "journeys": [
      "authorization code with PKCE",
      "refresh rotation and logout",
      "client credentials",
      "brokered identity and account linking"
    ]
  },
  "policy": {
    "block_critical": true,
    "block_fixable_high": true,
    "automatic_patch_only": true,
    "minimum_stability_seconds": 600,
    "rpo_seconds": 60,
    "rto_seconds": 900
  }
}
~~~

Never emit credentials, client secrets, signing material, tokens, user exports, database addresses containing
credentials, or personal data. Customization source revisions and compatibility tests are mandatory because Keycloak's
private SPIs can break without an obvious release-note entry.
