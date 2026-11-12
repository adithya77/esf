# Private and large repositories

Two ways a run's repository reaches the sandbox, neither of which puts a
credential or the whole history inside the VM.

## Local repositories: one-commit snapshots

`factory run --local-path` moves exactly one commit: the requested revision and
its tree, with no history, other branches or tags.

1. On the worker host, the commit is fetched at depth 1 into a scratch
   repository and bundled. The registered repository is only read; nothing is
   written to it. The commit keeps its real SHA, so the baseline, patch and
   evidence name the same revision as the host.
2. The bundle is size-checked against `repositories.max_snapshot_bytes`
   (default 1 GiB). An oversized snapshot fails before anything is sent:
   `snapshot exceeds the size limit: <path> at <sha> is N MiB, over
   repositories.max_snapshot_bytes (M MiB)`.
3. The bundle is streamed into the sandbox when the provider supports it
   (Baseten does, in 5 MiB parts). Otherwise it is written in 8 MiB parts that
   are joined inside the sandbox, so the worker never holds the whole snapshot
   in memory.
4. Inside the sandbox the commit is declared shallow, fetched from the bundle,
   and checked out. The bundle is then deleted.

The agent sees one commit (`git log` shows only the baseline), with no tags,
so `git describe` and version-from-tag builds do not work on a local source.
Only an uncredentialed remote clone still carries history.

Measured on Baseten (us-pdx-1, 4 GiB sandbox) on 2026-11-12, using a 1.3M-line
monorepo whose full pack is 760 MiB:

| | |
|---|---|
| snapshot | 93.8 MiB (the previous `--all` bundle was the full 760 MiB pack) |
| host snapshot build | about 2 s |
| upload | 18.6 s (5.1 MiB/s, sequential parts) |
| unpack + checkout | 4.6 s |
| whole repository preparation | 35.7 s |

## Private GitHub repositories: proxy-injected token

```toml
[repositories]
allowed           = ["https://github.com/acme/"]
github_token_file = "/etc/factory/github-token"   # 0600, read-only token
```

For an allowed `https://github.com/<owner>/<repo>` URL, repository preparation:

1. Replaces the sandbox's egress policy with one that denies everything except
   the two smart-HTTP requests a fetch makes: `GET
   github.com/<owner>/<repo>/info/refs` and `POST
   github.com/<owner>/<repo>/git-upload-pack` (also with `.git`). The
   provider's egress proxy adds `Authorization: Basic
   base64(x-access-token:<token>)` to those requests. Push (`git-receive-pack`)
   and every other path stay blocked, so even a token with write scope can
   only read this repository. Use a read-only token anyway.
2. Fetches the exact revision at depth 1 (`git fetch --depth 1 origin <rev>`).
   The revision must be a commit SHA or a ref name; expressions such as
   `main~1` are refused. Submodules are not fetched.
3. Restores the run's own egress policy, which withdraws the route and the
   token. This happens even if the fetch failed.

The token is read by the worker, sent only to the provider's control plane as
a write-only proxy secret, and registered with the redactor. It is never in
workflow history, evidence, the sandbox environment, or the repository's
`.git/config`.

Once a token is set, every `https://github.com` repository goes through this
path, public ones included. It is shallow (depth 1, no tags), takes only a
commit SHA or a ref name, and fetches no submodules or Git LFS objects.

Configuration is checked at startup:

- The sandbox provider must support egress credential injection (Cube and
  Baseten do), and its control plane must use HTTPS.
- Every `[egress.<name>]` policy must set `allow_internet`. With
  `acknowledge_open_egress = true`, every scope must also name a policy. The
  run's policy is restored after the fetch, and "the deployment default"
  cannot be restored exactly on every provider.
- The token file must exist and be owner-only when the worker starts.

It fails closed. A provider without runtime network control is refused
(`cannot inject the repository credential at its egress proxy`). So is a
provider that rejects the clone policy. If the run's policy cannot be
restored, the activity fails rather than run repository or agent code with
the route in place. Non-GitHub and non-HTTPS URLs are cloned without
credentials, as before.

Baseten matches paths as prefixes (see [baseten.md](baseten.md)); the two
endpoint paths admit nothing else a git client sends.
