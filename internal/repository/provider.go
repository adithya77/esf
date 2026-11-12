// Package repository prepares a repository inside a sandbox.
//
// Two source kinds are supported:
//
//   - SourceRemote clones a git URL. The URL must pass operator validation.
//   - SourceLocal snapshots one commit of a repository on the FACTORY HOST:
//     the requested revision and its tree, with no other refs and no history.
//     The snapshot travels as a git bundle and keeps the commit's real SHA, so
//     patches and evidence refer to the same revision as the host. This is
//     how the end-to-end acceptance test runs entirely offline and without
//     touching any real remote repository.
//
// Packing a host repository into a bundle does not execute repository code, so
// the "the host must not run untrusted repository code" rule still holds.
//
// Nothing in this package pushes, creates a branch on a remote, or opens a pull
// request.
package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mitkox/esf/internal/sandbox"
)

// Kind identifies where a repository comes from.
type Kind string

const (
	// SourceRemote clones over the network from a git URL.
	SourceRemote Kind = "remote"
	// SourceLocal packs a host-side repository into the sandbox.
	SourceLocal Kind = "local"
)

// ErrRepositoryRejected reports a repository the operator policy disallows.
var ErrRepositoryRejected = errors.New("repository: rejected by policy")

// Request identifies the repository and revision to prepare.
type Request struct {
	// Kind selects the source. Empty means SourceRemote.
	Kind Kind
	// URL is the git URL for SourceRemote.
	URL string
	// LocalPath is a host path for SourceLocal.
	LocalPath string
	// Revision is the exact revision to check out. Required: a run must be
	// reproducible, so "whatever HEAD happens to be" is not acceptable.
	Revision string
	// DestDir is the absolute in-sandbox directory to clone into.
	DestDir string
	// Shallow fetches only the requested revision of a remote repository
	// (depth 1, no other refs, no submodules). Revision must then be a full
	// commit SHA or a ref name the remote advertises. Local sources are
	// always shallow.
	Shallow bool
}

// Baseline records exactly what the agent started from.
type Baseline struct {
	Kind           Kind              `json:"kind"`
	Source         string            `json:"source"`
	RequestedRev   string            `json:"requested_revision"`
	SHA            string            `json:"sha"`
	Branch         string            `json:"branch,omitempty"`
	Status         string            `json:"status_porcelain"`
	LockfileHashes map[string]string `json:"lockfile_hashes,omitempty"`
	// Shallow records that only the baseline commit (no history) is present.
	Shallow bool `json:"shallow,omitempty"`
	// Credential names how a remote fetch authenticated, never the secret.
	Credential string `json:"credential,omitempty"`
	// SnapshotBytes is the size of the local snapshot moved into the sandbox.
	SnapshotBytes int64     `json:"snapshot_bytes,omitempty"`
	PreparedAt    time.Time `json:"prepared_at"`
}

// Provider prepares repositories.
type Provider struct {
	allowed    []string
	localPaths []string
	// maxSnapshotBytes bounds a local snapshot. Zero means DefaultMaxSnapshotBytes.
	maxSnapshotBytes int64
	log              *slog.Logger
	// runHostCommand allows tests to replace host-side git invocation.
	runHostCommand func(ctx context.Context, dir string, argv ...string) (string, error)
}

// Option customizes a Provider.
type Option func(*Provider)

// WithLocalPaths registers exact, canonical host repository directories. An
// empty list disables local sources. These paths and their Git metadata must
// be controlled by the operator, not by task submitters.
func WithLocalPaths(paths []string) Option {
	return func(p *Provider) { p.localPaths = append([]string(nil), paths...) }
}

// DefaultMaxSnapshotBytes bounds a local repository snapshot when the
// operator sets no limit. The snapshot is one commit and its tree, so this is
// about the size of a fresh shallow clone.
const DefaultMaxSnapshotBytes int64 = 1 << 30

// ErrSnapshotTooLarge reports a local snapshot over the configured bound.
var ErrSnapshotTooLarge = errors.New("repository: snapshot exceeds the size limit")

// WithMaxSnapshotBytes bounds the local snapshot moved into a sandbox. Zero
// or negative keeps the default.
func WithMaxSnapshotBytes(n int64) Option {
	return func(p *Provider) {
		if n > 0 {
			p.maxSnapshotBytes = n
		}
	}
}

// WithLogger sets the structured logger.
func WithLogger(log *slog.Logger) Option {
	return func(p *Provider) {
		if log != nil {
			p.log = log
		}
	}
}

// New creates a repository provider.
//
// allowed is the operator-controlled allowlist of git URL prefixes (for
// example "https://github.com/my-org/"). It may be empty, which disallows all
// remote repositories. Local repositories require WithLocalPaths.
func New(allowed []string, opts ...Option) *Provider {
	p := &Provider{
		allowed: append([]string(nil), allowed...),
		log:     slog.New(slog.DiscardHandler),
	}
	for _, opt := range opts {
		opt(p)
	}
	p.runHostCommand = runGitHost
	return p
}

// Allowed returns the configured remote allowlist.
func (p *Provider) Allowed() []string { return append([]string(nil), p.allowed...) }

// Validate checks a request against operator repository policy without touching
// a sandbox.
//
// It exists so the factory can reject a disallowed repository BEFORE any
// sandbox is created, and so the same rule is enforced at every entry point.
func (p *Provider) Validate(req Request) error {
	if err := req.validate(p.allowed); err != nil {
		return err
	}
	if req.Kind == SourceLocal {
		return validateLocalPath(req.LocalPath, p.localPaths)
	}
	return nil
}

// Prepare clones the repository into the sandbox and records the baseline.
func (p *Provider) Prepare(ctx context.Context, sb sandbox.Sandbox, req Request) (Baseline, error) {
	if err := p.Validate(req); err != nil {
		return Baseline{}, err
	}
	dest := req.DestDir
	if dest == "" {
		dest = "/workspace/repository"
	}
	dest = path.Clean(dest)
	if !path.IsAbs(dest) || path.Dir(dest) == dest {
		return Baseline{}, fmt.Errorf("%w: repository directory %q must be an absolute path below /", ErrRepositoryRejected, req.DestDir)
	}

	switch req.Kind {
	case SourceRemote:
		return p.prepareRemote(ctx, sb, req, dest)
	case SourceLocal:
		return p.prepareLocal(ctx, sb, req, dest)
	default:
		return Baseline{}, fmt.Errorf("repository: unknown source kind %q", req.Kind)
	}
}

func (p *Provider) prepareRemote(ctx context.Context, sb sandbox.Sandbox, req Request, dest string) (Baseline, error) {
	if req.Shallow {
		return p.prepareRemoteShallow(ctx, sb, req, dest)
	}
	reset, err := clearWorkspace(dest)
	if err != nil {
		return Baseline{}, err
	}
	steps := append(reset, []sandbox.Command{
		{
			// --no-tags and a single branch keep the clone small and fast, which
			// matters because the base image has ~900 MiB of disk.
			Argv:        []string{"git", "clone", "--no-tags", "--recurse-submodules", req.URL, dest},
			Timeout:     10 * time.Minute,
			Description: "clone repository",
		},
		{Argv: []string{"git", "-C", dest, "config", preparedMarker, "true"}, Description: "mark repository"},
	}...)
	if err := runAll(ctx, sb, steps); err != nil {
		return Baseline{}, err
	}

	return p.checkout(ctx, sb, Baseline{
		Kind:         SourceRemote,
		Source:       req.URL,
		RequestedRev: req.Revision,
	}, dest, req.Revision)
}

// prepareRemoteShallow fetches exactly the requested revision at depth 1.
//
// It makes the fewest, narrowest requests a clone can: one ref advertisement
// and one upload-pack, both under the repository's own path. That is what
// lets a proxy-injected credential be scoped to this repository alone.
func (p *Provider) prepareRemoteShallow(ctx context.Context, sb sandbox.Sandbox, req Request, dest string) (Baseline, error) {
	if !FetchableRevision(req.Revision) {
		return Baseline{}, fmt.Errorf("%w: a shallow fetch needs a commit SHA or ref name, not %q", ErrRepositoryRejected, req.Revision)
	}
	// GitHub and other hosts serve SHA-1 repositories; a SHA-256 remote fails
	// the fetch with git's own format error.
	init, err := freshRepository(dest, "sha1")
	if err != nil {
		return Baseline{}, err
	}
	steps := append(init, []sandbox.Command{
		{Argv: []string{"git", "-C", dest, "remote", "add", "origin", req.URL}, Description: "add remote"},
		{
			Argv:    []string{"git", "-C", dest, "fetch", "--depth", "1", "--no-tags", "--end-of-options", "origin", req.Revision + ":" + baselineRef},
			Timeout: 10 * time.Minute,
			// Authentication happens at the proxy; git must fail on a 401,
			// never wait for a username.
			Env:         map[string]string{"GIT_TERMINAL_PROMPT": "0"},
			Description: "fetch revision",
		},
	}...)
	if err := runAll(ctx, sb, steps); err != nil {
		return Baseline{}, err
	}
	return p.checkout(ctx, sb, Baseline{
		Kind:         SourceRemote,
		Source:       req.URL,
		RequestedRev: req.Revision,
		Shallow:      true,
	}, dest, baselineRef)
}

// baselineRef holds the fetched baseline in the sandbox repository.
const baselineRef = "refs/esf/base"

// preparedMarker is set in repositories this package initialises, so a retry
// may replace one it made itself and never anything else.
const preparedMarker = "esf.prepared"

// clearWorkspace makes dest an empty directory.
//
// dest comes from the run request, so it is never removed blindly: a
// directory is replaced only when it is a repository this package created
// (a retried preparation); an existing non-empty directory is refused, as
// `git clone` refuses it.
func clearWorkspace(dest string) ([]sandbox.Command, error) {
	if !strings.HasPrefix(dest, "/") {
		return nil, fmt.Errorf("repository: destination %q must be absolute", dest)
	}
	quoted, err := sandbox.QuoteArgv([]string{dest})
	if err != nil {
		return nil, err
	}
	script := "d=" + quoted + "\n" +
		"if [ -e \"$d\" ]; then\n" +
		"  if [ -d \"$d/.git\" ] && [ \"$(git --git-dir=\"$d/.git\" config --get " + preparedMarker + " 2>/dev/null)\" = true ]; then\n" +
		"    rm -rf -- \"$d\"\n" +
		"  elif [ -n \"$(ls -A -- \"$d\" 2>/dev/null)\" ]; then\n" +
		"    echo \"destination $d already exists and is not empty\" >&2; exit 1\n" +
		"  fi\n" +
		"fi\n" +
		"mkdir -p -- \"$d\"\n"
	return []sandbox.Command{{Script: script, Description: "clear workspace"}}, nil
}

// freshRepository makes dest an empty, marked repository of the given object
// format.
func freshRepository(dest, objectFormat string) ([]sandbox.Command, error) {
	if objectFormat != "sha1" && objectFormat != "sha256" {
		return nil, fmt.Errorf("repository: unsupported object format %q", objectFormat)
	}
	steps, err := clearWorkspace(dest)
	if err != nil {
		return nil, err
	}
	return append(steps,
		sandbox.Command{Argv: []string{"git", "init", "-q", "--object-format=" + objectFormat, dest}, Description: "initialise repository"},
		sandbox.Command{Argv: []string{"git", "-C", dest, "config", preparedMarker, "true"}, Description: "mark repository"},
	), nil
}

func (p *Provider) prepareLocal(ctx context.Context, sb sandbox.Sandbox, req Request, dest string) (Baseline, error) {
	// Recheck at the host-read boundary, even when admission already validated
	// the request. Workflow history and direct activity calls are not authority.
	if err := validateLocalPath(req.LocalPath, p.localPaths); err != nil {
		return Baseline{}, err
	}
	absPath, err := os.Stat(req.LocalPath)
	if err != nil {
		return Baseline{}, fmt.Errorf("repository: local path %q: %w", req.LocalPath, err)
	}
	if !absPath.IsDir() {
		return Baseline{}, fmt.Errorf("repository: local path %q is not a directory", req.LocalPath)
	}

	if err := p.validateLocalGitRoot(ctx, req.LocalPath); err != nil {
		return Baseline{}, err
	}

	snapshot, err := p.snapshotLocal(ctx, req)
	if err != nil {
		return Baseline{}, err
	}
	defer snapshot.cleanup()

	// A fixed scratch location, independent of the request's repository
	// directory, so the bundle can never land inside the destination.
	bundle := "/tmp/esf-snapshot-" + snapshot.sha[:16] + ".bundle"
	if err := writeSnapshot(ctx, sb, bundle, snapshot); err != nil {
		return Baseline{}, fmt.Errorf("repository: push snapshot into sandbox: %w", err)
	}

	steps, err := freshRepository(dest, snapshot.objectFormat)
	if err != nil {
		return Baseline{}, err
	}
	if err := runAll(ctx, sb, steps); err != nil {
		return Baseline{}, err
	}
	// The snapshot holds one commit without its parents. Declaring the
	// commit shallow first is what lets git accept it.
	if err := sb.WriteFile(ctx, path.Join(dest, ".git", "shallow"), []byte(snapshot.sha+"\n")); err != nil {
		return Baseline{}, fmt.Errorf("repository: mark snapshot shallow: %w", err)
	}
	steps = []sandbox.Command{
		{
			Argv:        []string{"git", "-C", dest, "fetch", "-q", "--no-tags", bundle, snapshotRef + ":" + baselineRef},
			Timeout:     5 * time.Minute,
			Description: "unpack snapshot",
		},
		{Argv: []string{"rm", "-f", "--", bundle}, Description: "remove snapshot bundle"},
	}
	if err := runAll(ctx, sb, steps); err != nil {
		return Baseline{}, err
	}

	return p.checkout(ctx, sb, Baseline{
		Kind:          SourceLocal,
		Source:        "local:" + req.LocalPath,
		RequestedRev:  req.Revision,
		Shallow:       true,
		SnapshotBytes: snapshot.size,
	}, dest, snapshot.sha)
}

// WarmBase describes a repository that Prepare already put into a sandbox,
// which Update can move to another revision.
type WarmBase struct {
	SHA            string            `json:"sha"`
	LockfileHashes map[string]string `json:"lockfile_hashes,omitempty"`
}

// Update moves a repository that Prepare left at base to req.Revision,
// sending only what the sandbox lacks: nothing when the revision is the base,
// otherwise the target commit and the objects its tree adds to the base's. A
// remote repository fetches the revision at depth 1 from its existing origin.
// The checkout is verified like a fresh one.
func (p *Provider) Update(ctx context.Context, sb sandbox.Sandbox, req Request, base WarmBase) (Baseline, error) {
	if err := p.Validate(req); err != nil {
		return Baseline{}, err
	}
	if base.SHA == "" {
		return Baseline{}, fmt.Errorf("repository: warm base has no commit")
	}
	dest := path.Clean(req.DestDir)
	if req.DestDir == "" {
		dest = "/workspace/repository"
	}
	switch req.Kind {
	case SourceLocal:
		return p.updateLocal(ctx, sb, req, dest, base)
	case SourceRemote:
		if !FetchableRevision(req.Revision) {
			return Baseline{}, fmt.Errorf("%w: a warm fetch needs a commit SHA or ref name, not %q", ErrRepositoryRejected, req.Revision)
		}
		return p.updateRemote(ctx, sb, req, dest)
	default:
		return Baseline{}, fmt.Errorf("repository: unknown source kind %q", req.Kind)
	}
}

// updateRemote fetches the revision at depth 1 from the warm repository's
// origin. The baseline ref is force-updated (the factory adds the "+"; a
// revision cannot contain one) because the target need not descend from the
// base.
func (p *Provider) updateRemote(ctx context.Context, sb sandbox.Sandbox, req Request, dest string) (Baseline, error) {
	if err := runAll(ctx, sb, []sandbox.Command{{
		Argv:        []string{"git", "-C", dest, "fetch", "--depth", "1", "--no-tags", "--end-of-options", "origin", "+" + req.Revision + ":" + baselineRef},
		Timeout:     10 * time.Minute,
		Env:         map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		Description: "fetch revision",
	}}); err != nil {
		return Baseline{}, err
	}
	return p.checkout(ctx, sb, Baseline{Kind: SourceRemote, Source: req.URL, RequestedRev: req.Revision, Shallow: true}, dest, baselineRef)
}

func (p *Provider) updateLocal(ctx context.Context, sb sandbox.Sandbox, req Request, dest string, base WarmBase) (Baseline, error) {
	if err := validateLocalPath(req.LocalPath, p.localPaths); err != nil {
		return Baseline{}, err
	}
	if err := p.validateLocalGitRoot(ctx, req.LocalPath); err != nil {
		return Baseline{}, err
	}
	resolved, err := p.runHostCommand(ctx, req.LocalPath, append([]string{"rev-parse", "--verify", "--quiet"}, revisionArgs(req.Revision)...)...)
	if err != nil {
		return Baseline{}, fmt.Errorf("%w: revision %q does not name a commit in %s", ErrRepositoryRejected, req.Revision, req.LocalPath)
	}
	target := strings.TrimSpace(resolved)
	out := Baseline{Kind: SourceLocal, Source: "local:" + req.LocalPath, RequestedRev: req.Revision, Shallow: true}
	if target == base.SHA {
		return p.checkout(ctx, sb, out, dest, target)
	}

	var snap localSnapshot
	if _, missing := p.runHostCommand(ctx, req.LocalPath, "cat-file", "-e", base.SHA+"^{commit}"); missing == nil {
		snap, err = p.treeDelta(ctx, req.LocalPath, base.SHA, target)
	} else {
		// The base is gone from the host (rewritten or collected): send the
		// target's whole tree, as a cold preparation would.
		snap, err = p.snapshotLocal(ctx, Request{LocalPath: req.LocalPath, Revision: target})
	}
	if err != nil {
		return Baseline{}, err
	}
	// The target is shallow in the sandbox: its tree is complete, its
	// history is not, whatever shape the history between base and target has.
	if err := sb.WriteFile(ctx, path.Join(dest, ".git", "shallow"), []byte(base.SHA+"\n"+target+"\n")); err != nil {
		snap.cleanup()
		return Baseline{}, fmt.Errorf("repository: mark target shallow: %w", err)
	}
	defer snap.cleanup()
	bundle := "/tmp/esf-snapshot-" + target[:16] + ".bundle"
	if err := writeSnapshot(ctx, sb, bundle, snap); err != nil {
		return Baseline{}, fmt.Errorf("repository: push snapshot into sandbox: %w", err)
	}
	if err := runAll(ctx, sb, []sandbox.Command{
		// Forced: the target need not descend from the current baseline ref.
		{Argv: []string{"git", "-C", dest, "fetch", "-q", "--no-tags", bundle, "+" + snapshotRef + ":" + baselineRef}, Timeout: 5 * time.Minute, Description: "unpack snapshot"},
		{Argv: []string{"rm", "-f", "--", bundle}, Description: "remove snapshot bundle"},
	}); err != nil {
		return Baseline{}, err
	}
	out.SnapshotBytes = snap.size
	return p.checkout(ctx, sb, out, dest, target)
}

// treeDelta bundles the target commit with exactly the objects its tree
// needs beyond the base's tree: what a warm sandbox, which already holds the
// base, lacks. History between the two is not sent, so merges, rewinds and
// unrelated histories all work; the sandbox marks the target shallow.
//
// The bundle is written directly (header plus a pack from git pack-objects),
// because git bundle can only cut history ranges, which drag in the parents
// of every merge. The host repository is only read.
func (p *Provider) treeDelta(ctx context.Context, local, base, target string) (localSnapshot, error) {
	format, err := p.runHostCommand(ctx, local, "rev-parse", "--show-object-format")
	if err != nil {
		return localSnapshot{}, err
	}
	format = strings.TrimSpace(format)
	objects, err := p.runHostCommand(ctx, local, "rev-list", "--objects", "--no-object-names", target+"^{tree}", "--not", base+"^{tree}")
	if err != nil {
		return localSnapshot{}, fmt.Errorf("repository: list objects for %s: %w", target[:12], err)
	}
	scratch, err := os.MkdirTemp("", "factory-delta-*")
	if err != nil {
		return localSnapshot{}, fmt.Errorf("repository: create snapshot directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(scratch) }
	file := filepath.Join(scratch, "delta.bundle")
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		cleanup()
		return localSnapshot{}, err
	}
	header := "# v2 git bundle\n"
	if format == "sha256" {
		header = "# v3 git bundle\n@object-format=sha256\n"
	}
	if _, err := fmt.Fprintf(f, "%s%s %s\n\n", header, target, snapshotRef); err != nil {
		f.Close()
		cleanup()
		return localSnapshot{}, err
	}
	list := target + "\n" + objects
	if err := runGitHostIO(ctx, local, strings.NewReader(list), f, "pack-objects", "--stdout", "-q"); err != nil {
		f.Close()
		cleanup()
		return localSnapshot{}, fmt.Errorf("repository: pack %s: %w", target[:12], err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return localSnapshot{}, err
	}
	info, err := os.Stat(file)
	if err != nil {
		cleanup()
		return localSnapshot{}, err
	}
	limit := p.maxSnapshotBytes
	if limit <= 0 {
		limit = DefaultMaxSnapshotBytes
	}
	if info.Size() > limit {
		cleanup()
		return localSnapshot{}, fmt.Errorf("%w: the change from %s to %s is %s, over repositories.max_snapshot_bytes (%s)",
			ErrSnapshotTooLarge, base[:12], target[:12], humanBytes(info.Size()), humanBytes(limit))
	}
	return localSnapshot{file: file, sha: target, objectFormat: format, size: info.Size(), cleanup: cleanup}, nil
}

// snapshotRef names the commit inside a snapshot bundle.
const snapshotRef = "refs/heads/esf-snapshot"

type localSnapshot struct {
	file         string
	sha          string
	objectFormat string
	size         int64
	cleanup      func()
}

// snapshotLocal bundles exactly one commit of a host repository: the
// requested revision and its tree, without parents, other refs, or tags.
//
// A bundle cannot be cut from a deep repository without its history, so the
// commit is first fetched at depth 1 into a scratch repository. The host
// repository is only read (through git upload-pack); nothing is written to it.
func (p *Provider) snapshotLocal(ctx context.Context, req Request) (localSnapshot, error) {
	resolved, err := p.runHostCommand(ctx, req.LocalPath, append([]string{"rev-parse", "--verify", "--quiet"}, revisionArgs(req.Revision)...)...)
	if err != nil {
		return localSnapshot{}, fmt.Errorf("%w: revision %q does not name a commit in %s", ErrRepositoryRejected, req.Revision, req.LocalPath)
	}
	sha := strings.TrimSpace(resolved)
	format, err := p.runHostCommand(ctx, req.LocalPath, "rev-parse", "--show-object-format")
	if err != nil {
		return localSnapshot{}, fmt.Errorf("repository: read object format: %w", err)
	}
	format = strings.TrimSpace(format)
	limit := p.maxSnapshotBytes
	if limit <= 0 {
		limit = DefaultMaxSnapshotBytes
	}
	// Estimate before writing anything to the host's temp space: the stored
	// size of the commit's tree is close to the bundle's, and a tree far over
	// the limit must not fill the disk on the way to being rejected.
	usage, err := p.runHostCommand(ctx, req.LocalPath, "rev-list", "--objects", "--no-walk", "--disk-usage", sha)
	n, perr := strconv.ParseInt(strings.TrimSpace(usage), 10, 64)
	switch {
	case err != nil || perr != nil:
		// git before 2.38 has no --disk-usage. The bound still holds below,
		// but only after the snapshot is written to temporary storage.
		p.log.WarnContext(ctx, "local snapshot size could not be estimated before writing; host git may predate 2.38",
			slog.String("repository", req.LocalPath))
	case n > limit:
		return localSnapshot{}, fmt.Errorf("%w: %s at %s holds about %s, over repositories.max_snapshot_bytes (%s)",
			ErrSnapshotTooLarge, req.LocalPath, sha[:12], humanBytes(n), humanBytes(limit))
	}

	scratch, err := os.MkdirTemp("", "factory-snapshot-*")
	if err != nil {
		return localSnapshot{}, fmt.Errorf("repository: create snapshot directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(scratch) }
	repo := filepath.Join(scratch, "repo")
	file := filepath.Join(scratch, "snapshot.bundle")
	// allowAnySHA1InWant applies to this one upload-pack process only; it lets
	// a commit be requested by SHA without changing the host repository.
	steps := [][]string{
		{"init", "-q", "--bare", "--object-format=" + format, repo},
		{"-C", repo, "fetch", "-q", "--depth", "1", "--no-tags",
			"--upload-pack", "git -c uploadpack.allowAnySHA1InWant=true upload-pack",
			req.LocalPath, sha + ":" + snapshotRef},
		{"-C", repo, "bundle", "create", "-q", file, snapshotRef},
	}
	for _, args := range steps {
		if _, err := p.runHostCommand(ctx, scratch, args...); err != nil {
			cleanup()
			return localSnapshot{}, fmt.Errorf("repository: snapshot local repository: %w", err)
		}
	}
	info, err := os.Stat(file)
	if err != nil {
		cleanup()
		return localSnapshot{}, fmt.Errorf("repository: read snapshot: %w", err)
	}
	if info.Size() > limit {
		cleanup()
		return localSnapshot{}, fmt.Errorf("%w: %s at %s is %s, over repositories.max_snapshot_bytes (%s)",
			ErrSnapshotTooLarge, req.LocalPath, sha[:12], humanBytes(info.Size()), humanBytes(limit))
	}
	p.log.InfoContext(ctx, "local repository snapshot",
		slog.String("repository.sha", sha), slog.Int64("snapshot.bytes", info.Size()))
	return localSnapshot{file: file, sha: sha, objectFormat: format, size: info.Size(), cleanup: cleanup}, nil
}

// writeSnapshot streams the snapshot when the provider can, so a large one
// never has to fit in the worker's memory; otherwise it is read once, already
// bounded by the size limit.
func writeSnapshot(ctx context.Context, sb sandbox.Sandbox, dest string, snap localSnapshot) error {
	f, err := os.Open(snap.file)
	if err != nil {
		return err
	}
	defer f.Close()
	if streamer, ok := sb.(sandbox.FileStreamer); ok {
		return streamer.WriteFileFrom(ctx, dest, f, snap.size)
	}
	// Without streaming, the snapshot goes in bounded parts that are joined
	// inside the sandbox, so worker memory never holds more than one part.
	chunk := make([]byte, snapshotPartBytes)
	var parts []string
	for offset, i := int64(0), 0; offset < snap.size; offset, i = offset+snapshotPartBytes, i+1 {
		n := min(snapshotPartBytes, snap.size-offset)
		if _, err := io.ReadFull(f, chunk[:n]); err != nil {
			return fmt.Errorf("read snapshot: %w", err)
		}
		part := fmt.Sprintf("%s.part-%06d", dest, i)
		if err := sb.WriteFile(ctx, part, chunk[:n]); err != nil {
			return err
		}
		parts = append(parts, part)
	}
	if len(parts) == 1 {
		return runAll(ctx, sb, []sandbox.Command{{Argv: []string{"mv", "-f", "--", parts[0], dest}, Description: "place snapshot"}})
	}
	argv := append([]string{"sh", "-c", `out="$1"; shift; cat -- "$@" > "$out" && rm -f -- "$@"`, "join-snapshot", dest}, parts...)
	return runAll(ctx, sb, []sandbox.Command{{Argv: argv, Timeout: 5 * time.Minute, Description: "join snapshot parts"}})
}

// snapshotPartBytes bounds one write when the provider cannot stream. A
// variable only so tests can force several parts.
var snapshotPartBytes int64 = 8 << 20

func humanBytes(n int64) string {
	const mib = 1 << 20
	if n >= mib {
		return fmt.Sprintf("%.1f MiB", float64(n)/mib)
	}
	return fmt.Sprintf("%d bytes", n)
}

// checkout checks out the exact revision and records the baseline.
//
// resolve is what names the revision inside the sandbox: the requested
// revision for a full clone, the fetched baseline ref or snapshot SHA
// otherwise. base.RequestedRev keeps the caller's spelling for evidence.
func (p *Provider) checkout(ctx context.Context, sb sandbox.Sandbox, base Baseline, dest, resolve string) (Baseline, error) {
	// Identity is set inside the sandbox so the agent can commit if it needs to.
	identity := []sandbox.Command{
		{Argv: []string{"git", "-C", dest, "config", "user.email", "factory@localhost"}, Description: "git identity email"},
		{Argv: []string{"git", "-C", dest, "config", "user.name", "Factory"}, Description: "git identity name"},
		{Argv: []string{"git", "-C", dest, "config", "advice.detachedHead", "false"}, Description: "quiet detached head"},
	}
	if err := runAll(ctx, sb, identity); err != nil {
		return Baseline{}, err
	}

	// Resolve the requested revision to a full SHA first so the recorded
	// baseline is unambiguous and the checkout is pinned.
	rev, err := runOne(ctx, sb, dest, append([]string{"rev-parse"}, revisionArgs(resolve)...)...)
	if err != nil {
		return Baseline{}, err
	}
	sha := strings.TrimSpace(rev.Stdout)
	if sha == "" {
		return Baseline{}, fmt.Errorf("repository: could not resolve revision %q", base.RequestedRev)
	}

	checkout, err := sb.Execute(ctx, sandbox.Command{
		Argv:        []string{"git", "-C", dest, "checkout", "--detach", "--force", sha},
		Timeout:     2 * time.Minute,
		Description: "checkout exact revision",
	})
	if err != nil {
		return Baseline{}, fmt.Errorf("repository: checkout %s: %w", sha, err)
	}
	if !checkout.Succeeded() {
		return Baseline{}, fmt.Errorf("repository: checkout %s failed (exit %d): %s",
			sha, checkout.ExitCode, truncate(checkout.Stderr, 400))
	}

	// The agent must start from exactly the resolved commit, and from the
	// requested one when the request named a full SHA. A stale or different
	// tree fails here rather than producing evidence about the wrong code.
	head, err := runOne(ctx, sb, dest, "rev-parse", "HEAD")
	if err != nil {
		return Baseline{}, err
	}
	if got := strings.TrimSpace(head.Stdout); got != sha {
		return Baseline{}, fmt.Errorf("repository: HEAD is %s after checking out %s", got, sha)
	}
	if isFullSHA(base.RequestedRev) && !strings.EqualFold(base.RequestedRev, sha) {
		return Baseline{}, fmt.Errorf("repository: requested %s but prepared %s", base.RequestedRev, sha)
	}

	status, err := runOne(ctx, sb, dest, "status", "--porcelain")
	if err != nil {
		return Baseline{}, err
	}
	branch, err := runOne(ctx, sb, dest, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return Baseline{}, err
	}

	base.SHA = sha
	base.Status = strings.TrimSpace(status.Stdout)
	base.Branch = strings.TrimSpace(branch.Stdout)
	base.PreparedAt = time.Now().UTC()
	base.LockfileHashes = p.hashLockfiles(ctx, sb, dest)
	return base, nil
}

// FetchableRevision reports whether a revision can be fetched by name from a
// remote at depth 1: a commit SHA or a ref name, not an expression such as
// main~1 or v1^{}.
func FetchableRevision(rev string) bool { return !strings.ContainsAny(rev, ":+*^~ ") }

// isFullSHA reports whether a revision is a complete SHA-1 or SHA-256 object
// name, which must then match the prepared commit exactly.
func isFullSHA(rev string) bool {
	if len(rev) != 40 && len(rev) != 64 {
		return false
	}
	for _, r := range rev {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

// revisionArgs renders a revision for `git rev-parse`.
//
// A revision beginning with "-" would otherwise be parsed as an option, so
// --end-of-options terminates option parsing first. The result is always passed
// as a structured argv element, never as shell text.
func revisionArgs(revision string) []string {
	if strings.HasPrefix(revision, "-") {
		return []string{"--end-of-options", revision + "^{commit}"}
	}
	return []string{revision + "^{commit}"}
}

// lockfileCandidates are dependency lockfiles whose hashes are recorded so a
// run is reproducible even when the agent changes dependencies.
var lockfileCandidates = []string{
	"go.sum", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
	"requirements.txt", "poetry.lock", "Pipfile.lock", "Cargo.lock",
	"Gemfile.lock", "composer.lock", "bun.lock", "bun.lockb",
}

func (p *Provider) hashLockfiles(ctx context.Context, sb sandbox.Sandbox, dest string) map[string]string {
	hashes := map[string]string{}
	for _, name := range lockfileCandidates {
		file := path.Join(dest, name)
		data, err := sb.ReadFile(ctx, file)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(data)
		hashes[name] = hex.EncodeToString(sum[:])
	}
	if len(hashes) == 0 {
		return nil
	}
	return hashes
}

// HeadSHA returns the current HEAD of the repository in the sandbox.
func (p *Provider) HeadSHA(ctx context.Context, sb sandbox.Sandbox, dest string) (string, error) {
	out, err := runOne(ctx, sb, dest, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out.Stdout), nil
}

// Status returns `git status --porcelain` for the repository.
func (p *Provider) Status(ctx context.Context, sb sandbox.Sandbox, dest string) (string, error) {
	out, err := runOne(ctx, sb, dest, "status", "--porcelain")
	if err != nil {
		return "", err
	}
	return out.Stdout, nil
}

// Patch returns the complete diff of the agent's changes, including untracked
// files.
//
// `git add -A` stages everything and `git diff --cached <baseline>` renders
// changes against the revision the agent started from. Comparing with HEAD
// would let an agent hide its entire contribution by committing it first.
func (p *Provider) Patch(ctx context.Context, sb sandbox.Sandbox, dest, baseline string) (string, error) {
	if baseline == "" {
		return "", fmt.Errorf("repository: baseline revision is required to collect a patch")
	}
	steps := []sandbox.Command{
		{Argv: []string{"git", "-C", dest, "add", "-A"}, Timeout: 2 * time.Minute, Description: "stage all changes"},
		{
			Argv:        []string{"git", "-C", dest, "diff", "--cached", "--no-color", "--no-ext-diff", "--binary", baseline},
			Timeout:     2 * time.Minute,
			Description: "render patch",
		},
	}
	var patch string
	for _, step := range steps {
		exec, err := sb.Execute(ctx, step)
		if err != nil {
			return "", fmt.Errorf("repository: %s: %w", step.Description, err)
		}
		if !exec.Succeeded() {
			return "", fmt.Errorf("repository: %s failed (exit %d): %s",
				step.Description, exec.ExitCode, truncate(exec.Stderr, 400))
		}
		patch = exec.Stdout
	}
	return patch, nil
}

// runOne runs a single git subcommand against the repository.
func runOne(ctx context.Context, sb sandbox.Sandbox, dest string, args ...string) (sandbox.Execution, error) {
	argv := append([]string{"git", "-C", dest}, args...)
	exec, err := sb.Execute(ctx, sandbox.Command{Argv: argv})
	if err != nil {
		return sandbox.Execution{}, fmt.Errorf("repository: git %s: %w", strings.Join(args, " "), err)
	}
	if !exec.Succeeded() {
		return exec, fmt.Errorf("repository: git %s failed (exit %d): %s",
			strings.Join(args, " "), exec.ExitCode, truncate(exec.Stderr, 400))
	}
	return exec, nil
}

func runAll(ctx context.Context, sb sandbox.Sandbox, steps []sandbox.Command) error {
	for _, step := range steps {
		exec, err := sb.Execute(ctx, step)
		if err != nil {
			return fmt.Errorf("repository: %s: %w", step.Description, err)
		}
		if !exec.Succeeded() {
			return fmt.Errorf("repository: %s failed (exit %d): %s",
				step.Description, exec.ExitCode, truncate(exec.Stderr, 400))
		}
	}
	return nil
}

// HashTask returns a stable hash of the task text, recorded so a run's input is
// verifiable without storing the text in every field.
func HashTask(task string) string {
	sum := sha256.Sum256([]byte(task))
	return hex.EncodeToString(sum[:])
}

// runGitHost runs a git command on the factory host.
// validateLocalGitRoot prevents Git's ancestor discovery from exporting a
// parent repository when the operator registered an ordinary subdirectory.
func (p *Provider) validateLocalGitRoot(ctx context.Context, dir string) error {
	bare, err := p.runHostCommand(ctx, dir, "rev-parse", "--is-bare-repository")
	if err != nil {
		return fmt.Errorf("%w: registered path is not a Git repository", ErrRepositoryRejected)
	}
	arg := "--show-toplevel"
	if strings.TrimSpace(bare) == "true" {
		arg = "--absolute-git-dir"
	}
	root, err := p.runHostCommand(ctx, dir, "rev-parse", arg)
	if err != nil {
		return fmt.Errorf("%w: cannot resolve registered Git root", ErrRepositoryRejected)
	}
	resolved, err := filepath.EvalSymlinks(strings.TrimSpace(root))
	if err != nil || resolved != dir {
		return fmt.Errorf("%w: registered path must be the Git repository root", ErrRepositoryRejected)
	}
	return nil
}

// runGitHostIO runs a host git command with explicit stdin and stdout,
// under the same environment rules as runGitHost.
func runGitHostIO(ctx context.Context, dir string, stdin io.Reader, stdout io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = hostGitEnv()
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// hostGitEnv drops GIT_* variables: host git is a local object transport,
// and ambient repository or config overrides must not redirect it.
func hostGitEnv() []string {
	var env []string
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "GIT_") {
			env = append(env, entry)
		}
	}
	return env
}

func runGitHost(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = hostGitEnv()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
