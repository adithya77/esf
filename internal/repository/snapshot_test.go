package repository

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mitkox/esf/internal/sandbox"
)

// hostSandbox runs commands on the test host. Paths are real host paths
// under a temp directory, so the repository flow runs end to end with real
// git, without a sandbox provider.
type hostSandbox struct {
	t        *testing.T
	streamed []string
	written  []string
}

func (h *hostSandbox) ID() string       { return "host" }
func (h *hostSandbox) Template() string { return "host" }
func (h *hostSandbox) Destroy(context.Context) error {
	return nil
}

func (h *hostSandbox) Execute(ctx context.Context, cmd sandbox.Command) (sandbox.Execution, error) {
	line, err := sandbox.CommandLine(cmd)
	if err != nil {
		return sandbox.Execution{}, err
	}
	c := exec.CommandContext(ctx, "sh", "-c", line)
	c.Dir = cmd.Dir
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "GIT_") {
			c.Env = append(c.Env, e)
		}
	}
	var stdout, stderr bytes.Buffer
	c.Stdout, c.Stderr = &stdout, &stderr
	err = c.Run()
	exit := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		exit = exitErr.ExitCode()
	} else if err != nil {
		return sandbox.Execution{}, err
	}
	return sandbox.Execution{ExitCode: exit, Stdout: stdout.String(), Stderr: stderr.String()}, nil
}

func (h *hostSandbox) WriteFile(_ context.Context, path string, data []byte) error {
	h.written = append(h.written, path)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func (h *hostSandbox) ReadFile(_ context.Context, path string) ([]byte, error) {
	return os.ReadFile(path)
}

// streamingHostSandbox also implements sandbox.FileStreamer.
type streamingHostSandbox struct{ hostSandbox }

func (h *streamingHostSandbox) WriteFileFrom(ctx context.Context, path string, r io.Reader, size int64) error {
	h.streamed = append(h.streamed, path)
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if int64(len(data)) != size {
		return errors.New("short read")
	}
	return h.hostSandbox.WriteFile(ctx, path, data)
}

// fixtureRepo builds a host repository with history, a second branch and a
// tag, so a test can tell whether any of them leak into the snapshot.
func fixtureRepo(t *testing.T) (dir string, shas []string) {
	t.Helper()
	dir = t.TempDir()
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=F", "-c", "user.email=f@test"}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q", "-b", "main")
	for i, content := range []string{"one\n", "two\n", "three\n"} {
		if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		run("add", "-A")
		run("commit", "-qm", "commit "+string(rune('1'+i)))
		shas = append(shas, run("rev-parse", "HEAD"))
	}
	run("tag", "v1", shas[0])
	run("branch", "side", shas[0])
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return resolved, shas
}

func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestLocalSnapshotHoldsOnlyTheRequestedCommit(t *testing.T) {
	repo, shas := fixtureRepo(t)
	p := New(nil, WithLocalPaths([]string{repo}))
	dest := filepath.Join(t.TempDir(), "workspace", "repository")
	sb := &hostSandbox{t: t}

	// A branch name resolves on the host; the baseline is the exact commit.
	base, err := p.Prepare(context.Background(), sb, Request{Kind: SourceLocal, LocalPath: repo, Revision: "main~1", DestDir: dest})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if base.SHA != shas[1] || !base.Shallow || base.SnapshotBytes <= 0 || base.RequestedRev != "main~1" {
		t.Fatalf("baseline: %+v", base)
	}
	if got := gitOut(t, dest, "rev-list", "--count", "HEAD"); got != "1" {
		t.Fatalf("history depth = %s, want 1", got)
	}
	if refs := gitOut(t, dest, "for-each-ref", "--format=%(refname)"); refs != baselineRef {
		t.Fatalf("other refs reached the sandbox: %q", refs)
	}
	if data, _ := os.ReadFile(filepath.Join(dest, "file.txt")); string(data) != "two\n" {
		t.Fatalf("worktree = %q", data)
	}
	if status := gitOut(t, dest, "status", "--porcelain"); status != "" {
		t.Fatalf("dirty checkout: %q", status)
	}
	if _, err := os.Stat("/tmp/esf-snapshot-" + shas[1][:16] + ".bundle"); !os.IsNotExist(err) {
		t.Fatal("the snapshot bundle was left in the sandbox")
	}
	// The host repository was only read.
	if refs := gitOut(t, repo, "for-each-ref", "--format=%(refname)"); strings.Contains(refs, "esf") {
		t.Fatalf("snapshot wrote refs to the host repository: %q", refs)
	}
}

func TestLocalSnapshotIsIdempotentOnRetry(t *testing.T) {
	repo, shas := fixtureRepo(t)
	p := New(nil, WithLocalPaths([]string{repo}))
	dest := filepath.Join(t.TempDir(), "repository")
	for i := 0; i < 2; i++ {
		base, err := p.Prepare(context.Background(), &hostSandbox{t: t}, Request{Kind: SourceLocal, LocalPath: repo, Revision: shas[2], DestDir: dest})
		if err != nil || base.SHA != shas[2] {
			t.Fatalf("attempt %d: %+v %v", i+1, base, err)
		}
	}
}

func TestLocalSnapshotStreamsWhenTheProviderCan(t *testing.T) {
	repo, shas := fixtureRepo(t)
	p := New(nil, WithLocalPaths([]string{repo}))
	dest := filepath.Join(t.TempDir(), "repository")
	sb := &streamingHostSandbox{hostSandbox{t: t}}
	if _, err := p.Prepare(context.Background(), sb, Request{Kind: SourceLocal, LocalPath: repo, Revision: shas[0], DestDir: dest}); err != nil {
		t.Fatal(err)
	}
	if len(sb.streamed) != 1 || sb.streamed[0] != "/tmp/esf-snapshot-"+shas[0][:16]+".bundle" {
		t.Fatalf("streamed = %v", sb.streamed)
	}
}

func TestLocalSnapshotIsBounded(t *testing.T) {
	repo, shas := fixtureRepo(t)
	p := New(nil, WithLocalPaths([]string{repo}), WithMaxSnapshotBytes(64))
	sb := &hostSandbox{t: t}
	_, err := p.Prepare(context.Background(), sb, Request{Kind: SourceLocal, LocalPath: repo, Revision: shas[0], DestDir: filepath.Join(t.TempDir(), "r")})
	if !errors.Is(err, ErrSnapshotTooLarge) || !strings.Contains(err.Error(), "repositories.max_snapshot_bytes") {
		t.Fatalf("err = %v", err)
	}
	if len(sb.written) != 0 {
		t.Fatal("an oversized snapshot was sent to the sandbox")
	}
}

func TestLocalSnapshotRejectsUnknownRevision(t *testing.T) {
	repo, _ := fixtureRepo(t)
	p := New(nil, WithLocalPaths([]string{repo}))
	_, err := p.Prepare(context.Background(), &hostSandbox{t: t}, Request{Kind: SourceLocal, LocalPath: repo, Revision: "no-such-branch", DestDir: filepath.Join(t.TempDir(), "r")})
	if !errors.Is(err, ErrRepositoryRejected) {
		t.Fatalf("err = %v", err)
	}
}

// The shallow remote path is exercised against a file:// remote; URL policy
// (https only, allowlist) is covered by validate_test.go and bypassed here.
func TestRemoteShallowFetchesOnlyTheRevision(t *testing.T) {
	repo, shas := fixtureRepo(t)
	gitOut(t, repo, "config", "uploadpack.allowAnySHA1InWant", "true") // GitHub allows SHA wants
	p := New(nil)
	for _, rev := range []string{shas[1], "main"} {
		dest := filepath.Join(t.TempDir(), "repository")
		base, err := p.prepareRemoteShallow(context.Background(), &hostSandbox{t: t}, Request{URL: "file://" + repo, Revision: rev, Shallow: true}, dest)
		if err != nil {
			t.Fatalf("%s: %v", rev, err)
		}
		want := shas[1]
		if rev == "main" {
			want = shas[2]
		}
		if base.SHA != want || !base.Shallow || base.RequestedRev != rev {
			t.Fatalf("%s: baseline %+v", rev, base)
		}
		if got := gitOut(t, dest, "rev-list", "--count", "HEAD"); got != "1" {
			t.Fatalf("%s: depth %s", rev, got)
		}
		if tags := gitOut(t, dest, "tag"); tags != "" {
			t.Fatalf("%s: tags fetched: %q", rev, tags)
		}
	}
}

func TestRemoteShallowRefusesRevisionExpressions(t *testing.T) {
	p := New(nil)
	for _, rev := range []string{"main~1", "a:refs/heads/x", "+main", "HEAD^"} {
		_, err := p.prepareRemoteShallow(context.Background(), &hostSandbox{t: t}, Request{URL: "https://github.com/o/r", Revision: rev, Shallow: true}, "/nonexistent")
		if !errors.Is(err, ErrRepositoryRejected) {
			t.Errorf("%q: %v", rev, err)
		}
	}
}

func TestPreparationNeverDeletesAForeignDirectory(t *testing.T) {
	repo, shas := fixtureRepo(t)
	p := New(nil, WithLocalPaths([]string{repo}))
	dest := filepath.Join(t.TempDir(), "workspace")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(dest, "harness-install")
	if err := os.WriteFile(keep, []byte("do not delete"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := p.Prepare(context.Background(), &hostSandbox{t: t}, Request{Kind: SourceLocal, LocalPath: repo, Revision: shas[0], DestDir: dest})
	if err == nil || !strings.Contains(err.Error(), "already exists and is not empty") {
		t.Fatalf("err = %v", err)
	}
	if data, _ := os.ReadFile(keep); string(data) != "do not delete" {
		t.Fatal("preparation deleted a directory it did not create")
	}
}

func TestLocalSnapshotSupportsSHA256Repositories(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=F", "-c", "user.email=f@test"}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q", "--object-format=sha256")
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "-qm", "one")
	sha := run("rev-parse", "HEAD")
	repo, _ := filepath.EvalSymlinks(dir)
	dest := filepath.Join(t.TempDir(), "repository")
	base, err := New(nil, WithLocalPaths([]string{repo})).Prepare(context.Background(), &hostSandbox{t: t}, Request{Kind: SourceLocal, LocalPath: repo, Revision: "HEAD", DestDir: dest})
	if err != nil || base.SHA != sha || len(sha) != 64 {
		t.Fatalf("baseline %+v err=%v", base, err)
	}
}

func TestSnapshotWithoutStreamingIsSentInBoundedParts(t *testing.T) {
	repo, shas := fixtureRepo(t)
	old := snapshotPartBytes
	snapshotPartBytes = 128
	t.Cleanup(func() { snapshotPartBytes = old })
	sb := &hostSandbox{t: t}
	dest := filepath.Join(t.TempDir(), "repository")
	base, err := New(nil, WithLocalPaths([]string{repo})).Prepare(context.Background(), sb, Request{Kind: SourceLocal, LocalPath: repo, Revision: shas[2], DestDir: dest})
	if err != nil || base.SHA != shas[2] {
		t.Fatalf("baseline %+v err=%v", base, err)
	}
	parts := 0
	for _, w := range sb.written {
		if strings.Contains(w, ".bundle.part-") {
			parts++
		}
	}
	if parts < 2 {
		t.Fatalf("parts written = %d (writes %v)", parts, sb.written)
	}
	if matches, _ := filepath.Glob("/tmp/esf-snapshot-" + shas[2][:16] + ".bundle*"); len(matches) != 0 {
		t.Fatalf("parts or bundle left behind: %v", matches)
	}
}

func TestRepositoryDirectoryIsNormalised(t *testing.T) {
	repo, shas := fixtureRepo(t)
	dest := filepath.Join(t.TempDir(), "repository") + "/"
	if _, err := New(nil, WithLocalPaths([]string{repo})).Prepare(context.Background(), &hostSandbox{t: t}, Request{Kind: SourceLocal, LocalPath: repo, Revision: shas[0], DestDir: dest}); err != nil {
		t.Fatalf("trailing slash: %v", err)
	}
	if _, err := New(nil, WithLocalPaths([]string{repo})).Prepare(context.Background(), &hostSandbox{t: t}, Request{Kind: SourceLocal, LocalPath: repo, Revision: shas[0], DestDir: "/"}); !errors.Is(err, ErrRepositoryRejected) {
		t.Fatalf("root destination: %v", err)
	}
}

func TestWarmUpdateShipsOnlyTheMissingCommits(t *testing.T) {
	repo, shas := fixtureRepo(t)
	p := New(nil, WithLocalPaths([]string{repo}))
	dest := filepath.Join(t.TempDir(), "repository")
	sb := &hostSandbox{t: t}
	base, err := p.Prepare(context.Background(), sb, Request{Kind: SourceLocal, LocalPath: repo, Revision: shas[0], DestDir: dest})
	if err != nil {
		t.Fatal(err)
	}
	warm := WarmBase{SHA: base.SHA, LockfileHashes: base.LockfileHashes}

	// Descendant: only base..target travels, and it is far smaller than a snapshot.
	got, err := p.Update(context.Background(), sb, Request{Kind: SourceLocal, LocalPath: repo, Revision: "main", DestDir: dest}, warm)
	if err != nil || got.SHA != shas[2] || got.RequestedRev != "main" {
		t.Fatalf("update to main: %+v %v", got, err)
	}
	if got.SnapshotBytes <= 0 || got.SnapshotBytes >= base.SnapshotBytes+1024 {
		t.Fatalf("range bundle = %d bytes (snapshot was %d)", got.SnapshotBytes, base.SnapshotBytes)
	}
	if data, _ := os.ReadFile(filepath.Join(dest, "file.txt")); string(data) != "three\n" {
		t.Fatalf("worktree = %q", data)
	}
	// The host repository was only read.
	if refs := gitOut(t, repo, "for-each-ref", "--format=%(refname)"); strings.Contains(refs, "esf") {
		t.Fatalf("host refs written: %q", refs)
	}

	// Back to the base: nothing to send.
	got, err = p.Update(context.Background(), sb, Request{Kind: SourceLocal, LocalPath: repo, Revision: shas[0], DestDir: dest}, warm)
	if err != nil || got.SHA != shas[0] || got.SnapshotBytes != 0 {
		t.Fatalf("update to base: %+v %v", got, err)
	}
}

func TestWarmUpdateToAnOlderCommit(t *testing.T) {
	repo, shas := fixtureRepo(t)
	p := New(nil, WithLocalPaths([]string{repo}))
	dest := filepath.Join(t.TempDir(), "repository")
	sb := &hostSandbox{t: t}
	base, err := p.Prepare(context.Background(), sb, Request{Kind: SourceLocal, LocalPath: repo, Revision: shas[2], DestDir: dest})
	if err != nil {
		t.Fatal(err)
	}
	// An older commit is not a descendant of the base.
	got, err := p.Update(context.Background(), sb, Request{Kind: SourceLocal, LocalPath: repo, Revision: shas[1], DestDir: dest}, WarmBase{SHA: base.SHA})
	if err != nil || got.SHA != shas[1] {
		t.Fatalf("update to an ancestor: %+v %v", got, err)
	}
	if data, _ := os.ReadFile(filepath.Join(dest, "file.txt")); string(data) != "two\n" {
		t.Fatalf("worktree = %q", data)
	}
}

func TestWarmRemoteUpdateFetchesTheRevision(t *testing.T) {
	repo, shas := fixtureRepo(t)
	gitOut(t, repo, "config", "uploadpack.allowAnySHA1InWant", "true")
	p := New(nil)
	dest := filepath.Join(t.TempDir(), "repository")
	sb := &hostSandbox{t: t}
	if _, err := p.prepareRemoteShallow(context.Background(), sb, Request{URL: "file://" + repo, Revision: shas[2], Shallow: true}, dest); err != nil {
		t.Fatal(err)
	}
	// Backwards, then forwards: both are forced updates of the baseline ref.
	for _, rev := range []string{shas[0], shas[1]} {
		got, err := p.updateRemote(context.Background(), sb, Request{URL: "file://" + repo, Revision: rev}, dest)
		if err != nil || got.SHA != rev {
			t.Fatalf("update to %s: %+v %v", rev[:8], got, err)
		}
	}
}

func TestCheckoutRefusesADifferentCommitThanRequested(t *testing.T) {
	repo, shas := fixtureRepo(t)
	p := New(nil, WithLocalPaths([]string{repo}))
	dest := filepath.Join(t.TempDir(), "repository")
	sb := &hostSandbox{t: t}
	if _, err := p.Prepare(context.Background(), sb, Request{Kind: SourceLocal, LocalPath: repo, Revision: shas[0], DestDir: dest}); err != nil {
		t.Fatal(err)
	}
	_, err := p.checkout(context.Background(), sb, Baseline{RequestedRev: shas[1]}, dest, shas[0])
	if err == nil || !strings.Contains(err.Error(), "requested") {
		t.Fatalf("a different commit than requested was accepted: %v", err)
	}
}

// The live failure: base..target over a merge needs the merged branch's
// parents, which a warm sandbox does not have. The tree delta does not care.
func TestWarmUpdateAcrossAMerge(t *testing.T) {
	repo, shas := fixtureRepo(t)
	git := func(args ...string) string {
		return gitOut(t, repo, append([]string{"-c", "user.name=F", "-c", "user.email=f@test"}, args...)...)
	}
	git("checkout", "-q", "-b", "feature", shas[0])
	if err := os.WriteFile(filepath.Join(repo, "feature.txt"), []byte("side\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", "-A")
	git("commit", "-qm", "side work")
	git("checkout", "-q", "main")
	git("merge", "-q", "--no-ff", "-m", "merge feature", "feature")
	merge := git("rev-parse", "HEAD")

	p := New(nil, WithLocalPaths([]string{repo}))
	dest := filepath.Join(t.TempDir(), "repository")
	sb := &hostSandbox{t: t}
	base, err := p.Prepare(context.Background(), sb, Request{Kind: SourceLocal, LocalPath: repo, Revision: shas[2], DestDir: dest})
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Update(context.Background(), sb, Request{Kind: SourceLocal, LocalPath: repo, Revision: merge, DestDir: dest}, WarmBase{SHA: base.SHA})
	if err != nil || got.SHA != merge {
		t.Fatalf("update to merge: %+v %v", got, err)
	}
	if data, _ := os.ReadFile(filepath.Join(dest, "feature.txt")); string(data) != "side\n" {
		t.Fatalf("merged file = %q", data)
	}
	if out := gitOut(t, dest, "fsck", "--connectivity-only", "--no-dangling"); out != "" {
		t.Fatalf("fsck: %s", out)
	}
}

func TestWarmUpdateWhenTheBaseIsGoneFromTheHost(t *testing.T) {
	repo, shas := fixtureRepo(t)
	p := New(nil, WithLocalPaths([]string{repo}))
	dest := filepath.Join(t.TempDir(), "repository")
	sb := &hostSandbox{t: t}
	if _, err := p.Prepare(context.Background(), sb, Request{Kind: SourceLocal, LocalPath: repo, Revision: shas[0], DestDir: dest}); err != nil {
		t.Fatal(err)
	}
	gone := strings.Repeat("ab", 20) // a base the host never had, as after a rewrite
	got, err := p.Update(context.Background(), sb, Request{Kind: SourceLocal, LocalPath: repo, Revision: shas[2], DestDir: dest}, WarmBase{SHA: gone})
	if err != nil || got.SHA != shas[2] {
		t.Fatalf("update: %+v %v", got, err)
	}
}
