# Baseten Sandboxes provider

ESF can run agents in [Baseten Sandboxes](https://docs.baseten.co/sandboxes/overview)
instead of CubeSandbox. Each sandbox is a Blaxel microVM in Baseten's cloud, so
the factory host needs no Cube install and no host network changes. Select it
with `[sandbox] provider = "baseten"`; Cube remains the default.

## How it works

- **Authentication.** The worker reads a Baseten API key from a 0600 file (or
  `BASETEN_API_KEY`) and exchanges it at `POST https://api.baseten.co/v1/token`
  for a two-hour sandbox token. The key itself is sent nowhere else and is
  registered with the factory's redactor. The token is cached and re-minted
  five minutes before it expires, or once on a 401.
- **Control plane.** Baseten Sandboxes run on Blaxel, and the minted token is
  accepted by Blaxel's control plane (`https://api.blaxel.ai/v0`) for the
  team's workspace (`baseten-<team id>`, discovered automatically when it is
  the only one). The provider uses Blaxel's API rather than Baseten's own
  sandbox API because only Blaxel's exposes the egress proxy: Baseten's
  [create](https://docs.baseten.co/reference/management-api/sandboxes/create-a-sandbox)
  and [update](https://docs.baseten.co/reference/management-api/sandboxes/update-a-sandbox)
  calls have no network fields. Using the Baseten-minted token on Blaxel's API is
  not documented by Baseten; the token's audience includes `api.blaxel.ai`.
- **Egress enforcement.** Every sandbox is created with the
  [`proxy` firewall ruleset](https://docs.blaxel.ai/Sandboxes/Proxy-domains#domain-filter-enforcement),
  which forces all egress through Blaxel's proxy. It can only be set at
  creation, so a sandbox that comes back without it is destroyed and the run
  fails closed. Runtime lockdown (`sandbox.NetworkUpdater`) then replaces the
  proxy's allowlist and routes on the live sandbox and reads the policy back;
  a policy the platform does not report is an error.
- **Credential injection.** `cube_egress` harnesses keep working: the model
  credential is sent to the control plane as a write-only
  [proxy secret](https://docs.blaxel.ai/Sandboxes/Proxy-secrets-injection) and
  injected by the proxy, replacing the agent's placeholder header. It never
  enters the microVM.
- **Execution.** Commands start detached through the sandbox's process API and
  are polled, because agent runs outlive a single HTTP request. Output is
  bounded inside the VM with the same wrapper Cube uses. Files go through the
  filesystem API; files over 5 MiB use its multipart upload.
- **Cleanup.** `Destroy` waits until the platform reports the sandbox
  `TERMINATED`, so cleanup verification never sees a half-deleted sandbox. An
  idle-TTL policy deletes any sandbox the factory loses track of.

## Configure

```toml
[sandbox]
provider      = "baseten"
base_packages = []          # bake prerequisites into the image instead

[baseten]
api_key_file = "/etc/factory/baseten-api-key"   # chmod 600
region       = "us-pdx-1"                       # must offer the egress proxy
template     = "blaxel/py-app:latest"           # sandbox image
memory_mib   = 4096
idle_timeout = "30m"
```

`factory doctor` checks the key, the workspace, and that the region reports the
egress proxy. The image is pulled at create time and is not checked by doctor.

### Choosing an image

The image needs everything the run uses, because a locked-down sandbox cannot
install packages: `git`, `sh`, `mkfifo`, `head`, `sha256sum`, the verification
toolchain, and the agent binary. Of the public images, `blaxel/py-app` (Debian
13) has git, bash and Python; `blaxel/claude-code` (Debian 12) has git, curl,
bash and the Claude CLI but no Python. The Alpine `blaxel/base-image` has none
of git, curl or bash.

Pin the agent, not just the tag. Blaxel's public images resolve by tag only
(they are not published to a registry the factory can pin by digest), so the
factory pins the agent binary instead and `factory agents verify` checks it
inside a fresh sandbox. `blaxel/claude-code:latest` verified on 2026-11-12:

```toml
[harnesses.claude]
type            = "claude"
binary          = "/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe"
preinstalled    = true
binary_sha256   = "17ed1a983a49404c4673de286419a8fd6617c92440a2e0f789bcc413a3b14de1"  # Claude Code 2.1.178
model           = "YOUR_APPROVED_CLAUDE_MODEL"
api_key_file    = "/etc/factory/anthropic-api-key"
credential_mode = "cube_egress"
base_url        = "https://api.anthropic.com"
```

When the tag moves, `agents verify` fails until the pin is updated. A
deployment that needs the whole image pinned should build its own
([Baseten](https://docs.baseten.co/sandboxes/manage-images.md)) from a
digest-pinned base, as with a versioned Cube template.

## Pi on a Baseten model

The Pi harness runs on Baseten with a Baseten-hosted model, and the model key
never enters the sandbox: the egress proxy injects it on
`inference.baseten.co` only.

### The image

`deploy/baseten/Dockerfile.pi` builds the sandbox image. Every input is pinned
by digest: Debian 13, the Blaxel sandbox API, and Node 26.13.0. Pi's runner
and runtime hashes match `agents/pi/inventory.json`, and
`scripts/verify-pi-inventory.py` checks them. It adds git, Python and curl. It
runs commands as uid 10001 (`agent`), so `hardening.require_non_root = true`
passes. It sets `NODE_USE_ENV_PROXY=1`: Blaxel routes all egress through its
proxy, and Node's `fetch` ignores `HTTPS_PROXY` without it, so every model
request would otherwise time out.

```sh
scripts/build-baseten-pi-image.sh esf-pi   # prints the immutable version tag
```

The script uploads only the Dockerfile and the committed Pi bundle, builds on
Baseten, and prints the version tags. Baseten assigns a content-addressed tag
per build; pin it, never `latest`.

### Configuration

```toml
[sandbox]
provider      = "baseten"
base_packages = []

[baseten]
api_key_file = "/etc/factory/baseten-api-key"
region       = "us-pdx-1"
template     = "sandbox/esf-pi:b242d6a510e452ed1aca3"
memory_mib   = 4096

[harnesses.pi]
type                 = "pi"
preinstalled         = true
binary               = "/opt/esf/agents/pi-runner.mjs"
binary_sha256        = "2f2b5191139a564050c98f0784e9be63893d47685abc6ac8a4049a942b201993"
runtime_binary       = "/opt/esf/agents/node"
runtime_sha256       = "0adde40d1b7dfa57c8bc83cbc319758c3ec6ebba21363bb2fa752ea6b267ad1b"
provider             = "baseten"
base_url             = "https://inference.baseten.co/v1"
model                = "deepseek-ai/DeepSeek-V4.1-Flash"
api                  = "openai-completions"
thinking_level       = "off"
max_process_restarts = 1
api_key_file         = "/etc/factory/baseten-api-key"
credential_mode      = "cube_egress"
timeout              = "20m"

[egress.locked]
allow_internet = false

[scopes.default]
egress = "locked"

[hardening]
require_non_root = true
```

The model is in Pi's embedded catalog, with context limits and pricing, so
no `catalog_cache` is needed. After repository preparation, the runtime policy
allows only `POST inference.baseten.co/v1/*` and injects
`Authorization: Bearer <key>` there. Pi sees the placeholder.

On 2026-11-12, run `run-312f2e7d15aa74d46e3503f3` completed a real task on
the fixture repository. It changed the greeting and added `farewell()` with a
test. Verification passed, the review gate approved it, and cleanup was
verified. The agent took 8.0 s, using 13,830 input tokens (6,656 cached) and
955 output tokens: about $0.0033 at catalog prices, an estimate rather than an
invoice. The agent ran as uid 10001.

## Egress policy mapping

| Factory policy | Blaxel proxy |
|---|---|
| deployment default / `allow_internet = true` | `allowedDomains = ["*"]` |
| open with `deny_out` | `forbiddenDomains = deny_out` (no allowlist, so no precedence question) |
| `allow_internet = false`, nothing allowed | `forbiddenDomains = ["*"]` (an empty allowlist means "allow all") |
| `allow_internet = false` with `allow_out` | `allowedDomains = allow_out`, `forbiddenDomains = deny_out` (deny wins; verified live) |
| L7 rule (host, methods, path) | allowlist entry `METHOD:...:host/path` |
| header injection | a proxy route on the rule's host with a `{{SECRET:...}}` header |

The provider **refuses** (error, nothing applied) what the proxy cannot enforce
as strictly as requested:

- IP addresses and CIDRs in `allow_out` / `deny_out`: the proxy filters by
  domain only. Private ranges and `169.254.169.254` bypass the proxy by design;
  the firewall still blocks direct connections to them (verified live).
- Rules pinning a port other than 443, a non-HTTPS scheme, or an SNI that
  differs from the host.
- Explicit deny rules (use `deny_out`).
- A credential-carrying host that is also allowed wholesale through
  `allow_out`, or that has rules both with and without injection: the proxy
  injects on every request to a routed host, so the credential would reach
  paths the rules did not allow.

## Differences from Cube

- **Rule paths are prefixes.** The proxy matches paths as start-anchored
  prefixes, so an exact Cube rule such as `POST /v1/messages` also admits
  deeper paths on the same host and method (`/v1/messages/batches`). The host,
  method and credential scope are unchanged. Exact matching is not expressible.
- **The egress probe is inconclusive, not failed.** A blocked request gets a
  refused CONNECT (with curl) or an unreachable network (without), which the
  probe records as undecided. It never reports a false "blocked", and a
  reachable canary still fails the run.
- **Sandboxes run as root** in the public images. The ESF Pi image
  (`deploy/baseten/Dockerfile.pi`) runs as uid 10001 with
  `BL_SANDBOX_USER_ENABLED=true`
  ([Blaxel](https://docs.blaxel.ai/Sandboxes/Non-root-user)), so
  `hardening.require_non_root = true` passes on it.
- **`base_packages` cannot install under a locked policy.** `apt-get update`
  exits zero when every fetch fails, so the install only succeeds when the
  packages are already in the image. Set `base_packages = []` and use an image
  that has them.
- **No suspend, resume, preview or snapshots** are advertised.
- **Production.** `factory doctor --profile production` fails the
  `sandbox_provider_production` check: the egress proxy is a vendor public
  preview, documented as not recommended for production.
- **Quotas.** Baseten allows 10 concurrent sandboxes per organisation by
  default; size `limits.worker_concurrency` accordingly.

## Verify

```sh
make test-baseten   # live provider tests; needs FACTORY_BASETEN_API_KEY_FILE
factory --config factory.toml doctor
```

`make test-baseten` creates and destroys its own sandboxes and asserts none are
left. It proves execution, file round-trips (including multipart), reattach,
timeouts, output bounding, runtime lockdown, method and path restriction,
credential injection without exposure, and deny precedence.

A disposable conformance run (the credential-free `.factory-agent.sh` fixture
registered as a `generic` harness under an `allow_internet = false` egress
policy) completed end to end on 2026-11-12: run
`run-f49c3c16c6e40999583f130a`, sandbox `esf-64727c29b3042bec`
(`blaxel/py-app:latest`, us-pdx-1), verified patch, both gates passed, cleanup
verified with zero sandboxes remaining.
