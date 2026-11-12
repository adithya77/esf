# Warm sandbox pool

A run normally creates a sandbox, moves its repository in, and starts from
nothing. The warm pool keeps a few sandboxes per repository already holding
the repository (and, optionally, prepared dependencies), so a run starts from
one of those instead. Off by default.

```toml
[sandbox.warm]
enabled         = true
size            = 2          # ready sandboxes per repository (quota: Baseten allows 10 in total)
max_age         = "1h"       # older members are destroyed, never handed out
prepare_command = []         # e.g. ["bun", "install", "--frozen-lockfile"]
prepare_timeout = "20m"

[[sandbox.warm.repositories]]
local_path = "/srv/repos/service"   # a repositories.local_paths entry
ref        = "HEAD"                 # the base members are prepared at

# [[sandbox.warm.repositories]]
# url = "https://github.com/acme/service"   # in repositories.allowed
# ref = "main"
```

## How a run uses it

1. **Fill.** The worker keeps every pool at `size`. It refills after each
   claim and checks at least once a minute. A member is a sandbox created
   from the deployment's template with open, stated egress. Each member:
   - runs the base packages and setup script;
   - has the repository prepared at `ref` (private GitHub repositories use the
     proxy-injected token path);
   - runs `prepare_command`;
   - passes a credential check: no git credential helper or extra auth
     header, no credentials in a remote URL, no `.git-credentials`, `.netrc`
     or `.npmrc` tokens. A member that fails is destroyed.

   A repository with submodules is never pooled. A warm update does not move
   submodules, so those runs stay cold.
2. **Claim.** If a ready member exists for the run's repository and the run
   needs nothing a member lacks, the run takes it. Otherwise the run goes
   cold, exactly as before. A run needs something a member lacks when it has:
   - its own environment or resource limits;
   - another template, repository directory, workspace packages or setup
     script;
   - for a remote source, a revision expression such as `main~1`, which a
     depth-1 fetch cannot name.

   The run's egress policy first replaces the fill-time one. Then the member
   is adopted: given the run's ownership labels and idle timeout, so recovery,
   leak detection and cleanup treat it as the run's own. A retried claim finds
   the adopted sandbox and applies the policy again. A member is used by one
   run and destroyed with it. It never returns to the pool, and its setup is
   not run a second time.
3. **Move to the revision.**
   - For a local source, the worker sends the target commit plus only the
     objects its tree adds to the base's, then marks the target shallow. This
     works for any history shape: descendants, merges, older or unrelated
     commits.
   - For a remote source, the sandbox fetches the revision at depth 1 from its
     origin.
   - Either way, HEAD must equal the resolved commit (and the requested SHA,
     when the run named one), or the run fails.
4. **Prepare again only if needed.** If a dependency lockfile changed since
   the base, `prepare_command` runs again under the run's egress policy. If
   that policy blocks the package registry, the run fails and says so.

Every run writes `preparation.json` to its evidence directory. It records:
- the path taken (`warm` or `cold`);
- how long acquiring the sandbox took;
- how long repository preparation took;
- the bytes transferred;
- for a warm run: the pool, base commit, member age, fill time, and whether
  the prepare step ran again.

Operators use `factory warm status`, `factory warm fill` and `factory warm
drain`. Drain destroys this deployment's pooled sandboxes, including any whose
pool record was lost. It leaves alone a member a run is claiming, a sandbox a
run has already adopted, and other deployments' pools.

## Measured

Measured on Baseten on 2026-11-12: fairground space-1 at `efde9ee`, a
1.3M-line monorepo with a 760 MiB pack, in a 4 GiB sandbox. The pool base
was `HEAD~3`, and HEAD is a merge.

| | acquire sandbox | repository preparation | transferred |
|---|---|---|---|
| cold | 3.6 s | 39.8 s | 98.3 MB |
| warm, base three commits behind | 2.0–2.3 s | 10.1–10.4 s | 64 KB |
| warm, run at the base commit | 1.0 s | 7.8 s | 0 |

A member took about 33 s to fill. The remaining warm time is fixed per-command
overhead: checkout, identity, status and lockfile hashing.

The dependency install was not measured. Fairground uses bun, its installed
`node_modules` is 6.9 GB, and Baseten sandbox disks are memory-backed, with
this account capped at 4096 MiB per sandbox. A full install cannot fit until
the cap is raised.

## Providers

The pool needs a provider that can relabel and re-police a live sandbox:
Baseten can. Cube cannot relabel, so configuration validation refuses
`sandbox.warm` on Cube. Blaxel snapshots and forks could replace pooled
sandboxes behind the same configuration once that preview is enabled for the
workspace.

## Refresh

Members rotate by `max_age`; the worker replaces them as they expire, so a
pool tracks its `ref` within `max_age` without a timer. A deployment that
wants a fixed cadence (for example, every 30 minutes, as Stripe's devboxes
do) can set `max_age = "30m"`, or run `factory warm drain && factory warm
fill` from a systemd timer. No timer is installed.
