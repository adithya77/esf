//go:build baseten

// Live measurement of a local-repository snapshot on Baseten. Run with:
//
//	FACTORY_BASETEN_API_KEY_FILE=... FACTORY_LIVE_LOCAL_REPO=/path/to/repo \
//	  go test -tags baseten ./internal/repository -run Live -v
package repository

import (
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mitkox/esf/internal/sandbox"
	"github.com/mitkox/esf/internal/sandbox/baseten"
)

// timedSandbox records how long the upload and each named step took.
type timedSandbox struct {
	sandbox.Sandbox
	mu    sync.Mutex
	steps map[string]time.Duration
}

func (t *timedSandbox) record(name string, d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.steps[name] += d
}

func (t *timedSandbox) Execute(ctx context.Context, cmd sandbox.Command) (sandbox.Execution, error) {
	started := time.Now()
	exec, err := t.Sandbox.Execute(ctx, cmd)
	t.record(cmd.Description, time.Since(started))
	return exec, err
}

func (t *timedSandbox) WriteFileFrom(ctx context.Context, path string, r io.Reader, size int64) error {
	started := time.Now()
	err := t.Sandbox.(sandbox.FileStreamer).WriteFileFrom(ctx, path, r, size)
	t.record("upload snapshot", time.Since(started))
	return err
}

func TestLiveLocalSnapshotOnBaseten(t *testing.T) {
	keyFile, repo := os.Getenv("FACTORY_BASETEN_API_KEY_FILE"), os.Getenv("FACTORY_LIVE_LOCAL_REPO")
	if keyFile == "" || repo == "" {
		t.Skip("set FACTORY_BASETEN_API_KEY_FILE and FACTORY_LIVE_LOCAL_REPO")
	}
	p, err := baseten.New(baseten.Config{
		APIKeyFile: keyFile, Region: "us-pdx-1", Template: "blaxel/py-app:latest", MemoryMiB: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	sb, err := p.Create(ctx, sandbox.Spec{Metadata: map[string]string{"origin": "factory-integration-test", "test": "local-snapshot"}, IdleTimeout: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		if err := p.Destroy(ctx, sb.ID()); err != nil {
			t.Errorf("Destroy: %v", err)
		}
		infos, _ := p.List(ctx)
		for _, info := range infos {
			if info.ID == sb.ID() {
				t.Errorf("sandbox %s leaked", sb.ID())
			}
		}
	})

	timed := &timedSandbox{Sandbox: sb, steps: map[string]time.Duration{}}
	rp := New(nil, WithLocalPaths([]string{repo}))
	started := time.Now()
	base, err := rp.Prepare(ctx, timed, Request{Kind: SourceLocal, LocalPath: repo, Revision: "HEAD", DestDir: "/workspace/repository"})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	total := time.Since(started)
	depth, err := sb.Execute(ctx, sandbox.Command{Argv: []string{"git", "-C", "/workspace/repository", "rev-list", "--count", "HEAD"}})
	if err != nil || strings.TrimSpace(depth.Stdout) != "1" {
		t.Fatalf("history depth %q err=%v", depth.Stdout, err)
	}
	upload := timed.steps["upload snapshot"]
	clone := timed.steps["unpack snapshot"] + timed.steps["checkout exact revision"]
	t.Logf("MEASURE repo=%s sha=%s snapshot=%.1f MiB upload=%s (%.1f MiB/s) unpack+checkout=%s total_prepare=%s",
		repo, base.SHA, float64(base.SnapshotBytes)/(1<<20), upload.Round(time.Millisecond),
		float64(base.SnapshotBytes)/(1<<20)/upload.Seconds(), clone.Round(time.Millisecond), total.Round(time.Millisecond))
	for name, d := range timed.steps {
		t.Logf("  step %-28s %s", name, d.Round(time.Millisecond))
	}
}
