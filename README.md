# cognito-broker

Mints an **AWS Cognito access token** for integration tests, from
coordinates held in **AWS Systems Manager** — using an ordinary AWS
session and nothing else.

```console
$ cognito-broker                  # JSON: token, expiry, non-secret profile
$ cognito-broker --format raw     # the token alone
```

---

## Why

Integration suites need a token the platform accepts. The usual ways to
get one are worse than they look:

**A standing test user.** Someone creates a Cognito user, hand-places a
username and password in a parameter store, and the suite authenticates
with `USER_PASSWORD_AUTH`. Nothing creates that user, nothing rotates
it, and no artifact answers *what can this credential reach*. It also
requires `USER_PASSWORD_AUTH` to stay enabled on the pool.

**A token service.** Standing up a broker that holds the credential and
hands out tokens works — but if the callers can already reach AWS, the
service is a hop that adds a deployment, a release cycle and an outage
mode without adding a capability.

This tool takes the third option: the credential lives in SSM, and
whoever may read it may mint a token. **Authorization becomes an IAM
question**, answered by the same policy that governs everything else the
caller can reach.

It is worth being explicit that this is *not* a broker in the sense of
holding a credential on someone's behalf. It holds nothing, runs
nowhere, and mediates between nothing — it reads a parameter tree and
calls a token endpoint. The name is for symmetry with its sibling
service, not a description of an architecture.

### `client_credentials`, not a user

The grant takes an app client id and secret and issues a token bound to
the client. No user, no password, no `USER_PASSWORD_AUTH`.

This is usually the right shape for tests, because platforms typically
do not read the token's `sub` for machine callers — tenancy arrives out
of band, in a header or a path. Check that before assuming it: if your
platform *does* authorize on `sub`, a client-credentials token
represents the client, not a person, and you want a different grant.

---

## How it works

```
      ┌──────────────────────────────────────────────┐
      │  cognito-broker                              │
      │                                              │
  ────┼─▶ 1. resolve   the AWS session (profile,     │
      │                or the default chain)         │
      │   2. read      SSM tree → client id,         │──▶ AWS SSM
      │                secret, endpoint, scopes      │
      │   3. exchange  client_credentials            │──▶ Cognito
      │   4. print     token + non-secret profile    │
      └──────────────────────────────────────────────┘
```

**Local and CI are the same command.** They differ only in how the AWS
session is obtained — a `credential_process` on a laptop, a pod identity
or assumed role in CI — which is a question the AWS credential chain
already answers. A suite that passes locally exercised the same path CI
will.

**A binary, not a library.** The suites that need this are written in
different languages. One binary they all shell out to is one
implementation; a library would be three, and three drift.

---

## Configuration

Two pieces, and the split between them is the point.

### 1. The SSM tree — where the coordinates live

```
/dms/e2e/devel/client_id        String
/dms/e2e/devel/client_secret    SecureString   ← the only secret
/dms/e2e/devel/token_url        String         https://{domain}/oauth2/token
/dms/e2e/devel/scopes           String         dms/api
/dms/e2e/devel/api_url          String         (any extra key is passed through)
```

Parameters are read **recursively and decrypted**, and keyed by their
leaf name — `/dms/e2e/devel/client_id` is `client_id` — so the tree can
move without every consumer changing.

`token_url` is the pool's **hosted** endpoint, `https://{domain}/oauth2/token`.
The `cognito-idp` API host does not serve this grant; pointing at it is
the most common way to get an unhelpful error from a correct setup.

Keys beyond the four required ones are passed through to the output, so
this is also where a suite's `api_url` or `pool_id` belongs.

### 2. `.cognito-broker.yaml` — what the repository commits

```yaml
token:
  region: eu-central-1
  profile: test          # which aws.ini profile to resolve credentials with
  path: /dms/e2e/devel   # which SSM tree to read
```

Found by walking up from the working directory, so a recipe run from a
package subdirectory finds it without passing `--config`. Every value
can also be a flag; the file is optional if you pass them all.

**Note what is absent: no role and no account.** Those belong in
`aws.ini`, which already carries them per face and is usually under
CODEOWNERS precisely because widening what CI may reach needs review.
Naming a role here would be a second way to grant AWS reach that routes
around that review.

`profile` is a **selector, not a grant** — it names an identity
`aws.ini` already defines. It is committed rather than left to the
caller's `AWS_PROFILE` because the choice belongs to the repository, and
because a CI default profile is often deliberately something else (a
runner's own pod identity) that cannot read the tree.

**Nor is the pool id, client id or endpoint here.** They live in SSM, so
rotating a client or moving a pool is an SSM write rather than a pull
request in every repository that authenticates against it.

---

## Output

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_at": "2026-09-01T12:00:00Z",
  "profile": {
    "client_id": "...",
    "api_url": "https://dms.devel.example.xyz",
    "pool_id": "eu-central-1_..."
  }
}
```

`profile` carries through every SSM key **except** anything
credential-shaped. That filter is deliberately over-eager: this output
lands in CI logs, where omitting a harmless key costs a config edit and
including a secret one costs a rotation.

`--format raw` prints the token alone, for `TOKEN=$(cognito-broker --format raw)`.

---

## IAM

The identity the profile resolves to needs:

| action | on |
|---|---|
| `ssm:GetParametersByPath` | `arn:aws:ssm:{region}:{account}:parameter{path}` |
| `kms:Decrypt` | the key encrypting the `SecureString` |

Missing `kms:Decrypt` alone is the confusing one: the read succeeds and
returns **ciphertext**, which then fails at Cognito as `invalid_client`
— reading as a wrong credential rather than a missing grant. This tool
always requests decryption so that failure surfaces at the SSM call
instead.

---

## Failure modes

| symptom | cause |
|---|---|
| `AccessDeniedException` on `GetParametersByPath` | the resolved identity lacks the grant above — an IAM fix, not a config one |
| `no parameters under "..."` | wrong path, wrong account, or the tree was never provisioned |
| `profile is missing ...` | the tree exists but is incomplete; the message names which keys |
| `invalid_client` from Cognito | usually the app client has no resource-server scope, **not** a wrong secret |
| `credential_process ... exit status 127` | the helper named in `aws.ini` is not on PATH (common under devbox, where a repository `bin/` is only on PATH inside the shell) |

---

## Install

```console
$ go install github.com/truvity/cognito-broker/cmd/cognito-broker@latest
```

or download a release archive.

---

## License

MIT — see [LICENSE](LICENSE).
