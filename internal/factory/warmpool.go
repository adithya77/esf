package factory

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/mitkox/esf/internal/repository"
	"github.com/mitkox/esf/internal/sandbox"
	"github.com/mitkox/esf/internal/tomlx"
)

// Warm pool defaults. The pool is small because every member is a live
// sandbox counted against the provider's quota (Baseten allows 10).
const (
	DefaultWarmPoolSize       = 2
	DefaultWarmMaxAge         = time.Hour
	DefaultWarmPrepareTimeout = 20 * time.Minute
	// warmPoolOrigin labels pool members so they are never mistaken for a
	// run's sandbox (or a leak) until a run claims them.
	warmPoolOrigin = "factory-pool"
	// warmFillSlack keeps an abandoned "filling" entry from being reaped
	// while a slow fill is still legitimately running.
	warmFillSlack = 10 * time.Minute
	// warmRefillInterval is the refill loop's heartbeat; claims also wake it.
	warmRefillInterval = time.Minute
	// warmClaimTimeout bounds a claim (re-police plus adoption); an entry
	// still "claiming" after it belongs to a claimer that died.
	warmClaimTimeout = 10 * time.Minute
	// Labels a claimed sandbox carries beside the run's ownership, so a
	// retried CreateSandbox can tell it came from the pool and re-apply the
	// run's policy.
	warmPoolLabel = "warm_pool"
	warmBaseLabel = "warm_base"
)

// WarmPoolConfig keeps prepared sandboxes ready per repository, so a run
// starts from a sandbox that already holds the repository (and its prepared
// dependencies) instead of creating one and moving the repository in.
//
// A member is used by exactly one run and destroyed with it; it is never
// returned to the pool. It holds no secrets: it is created without run
// environment, private repositories are fetched through the proxy-injected
// credential path, and a check refuses a member whose repository carries a
// credential helper or credentials in a remote URL.
type WarmPoolConfig struct {
	Enabled bool `toml:"enabled"`
	// Size is the number of ready sandboxes kept per repository.
	Size int `toml:"size"`
	// MaxAge discards a ready sandbox older than this; a run never gets one.
	MaxAge tomlx.Duration `toml:"max_age"`
	// PrepareCommand runs in the repository after it is checked out (for
	// example ["yarn", "install", "--immutable"]). A run re-runs it, under
	// the run's egress policy, only when a dependency lockfile changed
	// between the pool's base commit and the requested one.
	PrepareCommand []string `toml:"prepare_command"`
	// PrepareTimeout bounds one prepare run.
	PrepareTimeout tomlx.Duration `toml:"prepare_timeout"`
	// Repositories lists what to keep warm.
	Repositories []WarmRepository `toml:"repositories"`
}

// WarmRepository names one repository to keep warm, at a base ref.
type WarmRepository struct {
	// LocalPath is a registered repositories.local_paths entry.
	LocalPath string `toml:"local_path"`
	// URL is a remote repository in repositories.allowed.
	URL string `toml:"url"`
	// Ref is the base revision members are prepared at; runs fetch their
	// own revision on top. Default "HEAD".
	Ref string `toml:"ref"`
}

func (w WarmPoolConfig) size() int {
	if w.Size <= 0 {
		return DefaultWarmPoolSize
	}
	return w.Size
}

func (w WarmPoolConfig) maxAge() time.Duration {
	if w.MaxAge <= 0 {
		return DefaultWarmMaxAge
	}
	return w.MaxAge.Std()
}

func (w WarmPoolConfig) prepareTimeout() time.Duration {
	if w.PrepareTimeout <= 0 {
		return DefaultWarmPrepareTimeout
	}
	return w.PrepareTimeout.Std()
}

func (r WarmRepository) ref() string {
	if strings.TrimSpace(r.Ref) == "" {
		return "HEAD"
	}
	return strings.TrimSpace(r.Ref)
}

// source is the repository identity a run request is matched on.
func (r WarmRepository) source() string {
	if r.LocalPath != "" {
		return "local:" + r.LocalPath
	}
	return r.URL
}

func (r WarmRepository) request(dest string) repository.Request {
	if r.LocalPath != "" {
		return repository.Request{Kind: repository.SourceLocal, LocalPath: r.LocalPath, Revision: r.ref(), DestDir: dest}
	}
	return repository.Request{Kind: repository.SourceRemote, URL: r.URL, Revision: r.ref(), DestDir: dest}
}

// validateWarmPool checks the pool configuration. It is called by Validate
// only when the pool is enabled.
func (c Config) validateWarmPool(backend sandboxBackend) []string {
	w := c.Sandbox.Warm
	var problems []string
	if !backend.warmPool {
		problems = append(problems, fmt.Sprintf("sandbox.warm needs a provider that can relabel and re-police a live sandbox; %s cannot", c.SandboxProvider()))
	}
	if w.Size < 0 || w.Size > 10 {
		problems = append(problems, "sandbox.warm.size must be between 1 and 10 (0 means the default, 2)")
	}
	if w.MaxAge < 0 || w.PrepareTimeout < 0 {
		problems = append(problems, "sandbox.warm durations must not be negative")
	}
	if len(w.Repositories) == 0 {
		problems = append(problems, "sandbox.warm.repositories must list at least one repository")
	}
	probe := repository.New(c.Repositories.Allowed, repository.WithLocalPaths(c.Repositories.LocalPaths))
	for i, r := range w.Repositories {
		if (r.LocalPath == "") == (r.URL == "") {
			problems = append(problems, fmt.Sprintf("sandbox.warm.repositories[%d] needs exactly one of local_path or url", i))
			continue
		}
		if err := probe.Validate(r.request(DefaultRepositoryDir)); err != nil {
			problems = append(problems, fmt.Sprintf("sandbox.warm.repositories[%d]: %v", i, err))
		}
	}
	// A claimed member is re-policed with the run's egress policy, so the
	// policy must be stated (the same rule as a credentialed clone).
	problems = append(problems, c.requireStatedEgress("sandbox.warm")...)
	return problems
}

// requireStatedEgress lists egress configurations a feature that restores
// or applies a run's policy cannot reproduce exactly.
func (c Config) requireStatedEgress(feature string) []string {
	var problems []string
	names := make([]string, 0, len(c.Egress))
	for name := range c.Egress {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if c.Egress[name].AllowInternet == nil {
			problems = append(problems, fmt.Sprintf("%s: egress policy %q must set allow_internet", feature, name))
		}
	}
	if c.Hardening.AcknowledgeOpenEgress {
		scopes := make([]string, 0, len(c.Scopes))
		for name := range c.Scopes {
			scopes = append(scopes, name)
		}
		sort.Strings(scopes)
		for _, name := range scopes {
			if strings.TrimSpace(c.Scopes[name].Egress) == "" {
				problems = append(problems, fmt.Sprintf("%s: scope %q must name an egress policy (open egress is acknowledged, so it would otherwise run under the unstated deployment default)", feature, name))
			}
		}
	}
	return problems
}

// warmMember is one pooled sandbox.
type warmMember struct {
	// Token identifies the entry before its sandbox exists.
	Token     string              `json:"token"`
	SandboxID string              `json:"sandbox_id,omitempty"`
	State     string              `json:"state"`
	Base      repository.WarmBase `json:"base"`
	CreatedAt time.Time           `json:"created_at"`
	ReadyAt   time.Time           `json:"ready_at,omitempty"`
	ClaimedAt time.Time           `json:"claimed_at,omitempty"`
	// FillDuration and PrepareDuration are evidence for warm-vs-cold.
	FillDuration    time.Duration `json:"fill_duration,omitempty"`
	PrepareDuration time.Duration `json:"prepare_duration,omitempty"`
}

const (
	warmFilling  = "filling"
	warmReady    = "ready"
	warmClaiming = "claiming"
)

type warmPoolFile struct {
	Key      string       `json:"key"`
	Source   string       `json:"source"`
	Ref      string       `json:"ref"`
	Template string       `json:"template"`
	Members  []warmMember `json:"members"`
}

// WarmClaim is what a run records about the pooled sandbox it received.
type WarmClaim struct {
	PoolKey         string              `json:"pool_key"`
	Base            repository.WarmBase `json:"base"`
	MemberAge       time.Duration       `json:"member_age"`
	FillDuration    time.Duration       `json:"fill_duration"`
	PrepareDuration time.Duration       `json:"prepare_duration"`
}

// warmPool is the file-backed pool state, one JSON document per pool key
// under <data_dir>/warm, serialised with flock like the change store.
type warmPool struct {
	root string
}

func newWarmPool(dataDir string) (*warmPool, error) {
	root := filepath.Join(dataDir, "warm")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("warm pool: create %s: %w", root, err)
	}
	return &warmPool{root: root}, nil
}

// warmKey identifies a pool: the same repository, base ref, template,
// prepare step, base packages and setup script. Changing any of them starts a
// new pool rather than handing out sandboxes prepared differently.
func (c Config) warmKey(r WarmRepository) string {
	h := sha256.New()
	for _, part := range []string{r.source(), r.ref(), c.SandboxTemplate(), strings.Join(c.Sandbox.Warm.PrepareCommand, "\x00"),
		strings.Join(c.Sandbox.BasePackages, "\x00"), c.Sandbox.SetupScript} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// load reads a pool document without locking; a missing pool is empty.
func (p *warmPool) load(key string) (warmPoolFile, error) {
	var doc warmPoolFile
	data, err := os.ReadFile(filepath.Join(p.root, key+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return doc, nil
	}
	if err != nil {
		return doc, err
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return doc, fmt.Errorf("warm pool: decode %s: %w", key, err)
	}
	return doc, nil
}

// validPoolKey accepts only keys warmKey can produce, so a label read back
// from a sandbox can never name a path outside the pool directory.
func validPoolKey(key string) bool {
	if len(key) != 16 {
		return false
	}
	_, err := hex.DecodeString(key)
	return err == nil
}

// update runs fn on the pool document under its lock and saves the result.
func (p *warmPool) update(key string, fn func(*warmPoolFile)) error {
	unlock, err := lockFileIn(p.root, key+".lock")
	if err != nil {
		return err
	}
	defer unlock()
	path := filepath.Join(p.root, key+".json")
	var doc warmPoolFile
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("warm pool: decode %s: %w", key, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	doc.Key = key
	fn(&doc)
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// expired reports members a run must not get: ready ones past max age, and
// fills or claims that outlived any legitimate one.
func expired(m warmMember, now time.Time, maxAge, prepareTimeout time.Duration) bool {
	switch m.State {
	case warmReady:
		return now.Sub(m.ReadyAt) > maxAge
	case warmClaiming:
		return now.Sub(m.ClaimedAt) > warmClaimTimeout
	default:
		// A fill runs the setup script, the repository preparation and the
		// prepare command, each bounded by prepareTimeout.
		return now.Sub(m.CreatedAt) > 3*prepareTimeout+warmFillSlack
	}
}

// warmRepositoryFor returns the configured warm repository a run request
// matches, if any.
func (c Config) warmRepositoryFor(repositoryURL, localPath string) (WarmRepository, bool) {
	if !c.Sandbox.Warm.Enabled {
		return WarmRepository{}, false
	}
	for _, r := range c.Sandbox.Warm.Repositories {
		if (localPath != "" && r.LocalPath == localPath) || (localPath == "" && r.URL != "" && r.URL == repositoryURL) {
			return r, true
		}
	}
	return WarmRepository{}, false
}

// claimWarm hands a ready pooled sandbox to a run, or reports false so the
// run takes the cold path.
//
// The member stays in the pool file as "claiming" until it is adopted, so a
// concurrent drain leaves it alone. The run's egress policy is applied before
// the run's ownership: a crash in between leaves a pool-labelled sandbox
// (reaped as an expired claim), never a run-owned one with the fill-time
// policy. Any failure destroys the member; it is never returned or reused.
func (a *Activities) claimWarm(ctx context.Context, in CreateSandboxInput, spec sandbox.Spec) (CreateSandboxOutput, bool) {
	r, ok := a.cfg.warmRepositoryFor(in.Repository, in.LocalPath)
	if !ok || a.warm == nil || !a.warmEligible(in, spec) {
		return CreateSandboxOutput{}, false
	}
	adopter, ok := a.provider.(sandbox.Adopter)
	if !ok {
		return CreateSandboxOutput{}, false
	}
	key := a.cfg.warmKey(r)
	started := time.Now()
	var member warmMember
	var stale []warmMember
	now := time.Now()
	err := a.warm.update(key, func(doc *warmPoolFile) {
		kept := doc.Members[:0]
		for _, m := range doc.Members {
			switch {
			case expired(m, now, a.cfg.Sandbox.Warm.maxAge(), a.cfg.Sandbox.Warm.prepareTimeout()):
				stale = append(stale, m)
				continue
			case member.SandboxID == "" && m.State == warmReady:
				m.State, m.ClaimedAt = warmClaiming, now
				member = m
			}
			kept = append(kept, m)
		}
		doc.Members = kept
	})
	// Reaping is the refill loop's job; never make the run wait for it.
	go a.reapWarm(context.WithoutCancel(ctx), stale)
	if err != nil || member.SandboxID == "" {
		if err != nil {
			a.log.WarnContext(ctx, "warm pool unavailable; taking the cold path", slog.Any("error", err))
		}
		return CreateSandboxOutput{}, false
	}
	release := func() {
		_ = a.warm.update(key, func(doc *warmPoolFile) { doc.Members = removeSandbox(doc.Members, member.SandboxID) })
		// Only now does the pool count one member fewer: wake the refill.
		a.signalWarmRefill()
	}

	err = a.applyRunPolicy(ctx, member.SandboxID, in.Network)
	if err == nil {
		labels := maps.Clone(spec.Metadata)
		labels[warmPoolLabel], labels[warmBaseLabel] = key, member.Base.SHA
		err = adopter.Adopt(ctx, member.SandboxID, labels, spec.IdleTimeout)
	}
	release()
	if err != nil {
		a.log.WarnContext(ctx, "warm sandbox could not be claimed; taking the cold path", slog.Any("error", err))
		a.destroyWarm(ctx, []warmMember{member}, "claim failed")
		return CreateSandboxOutput{}, false
	}
	a.log.InfoContext(ctx, "warm sandbox claimed",
		slog.String("run.id", in.RunID), slog.String("sandbox.id", member.SandboxID),
		slog.Duration("member.age", now.Sub(member.ReadyAt)))
	return CreateSandboxOutput{
		SandboxID: member.SandboxID,
		Template:  spec.Template,
		Duration:  time.Since(started),
		Warm: &WarmClaim{
			PoolKey: key, Base: member.Base, MemberAge: now.Sub(member.ReadyAt),
			FillDuration: member.FillDuration, PrepareDuration: member.PrepareDuration,
		},
	}, true
}

// warmEligible reports whether a pooled sandbox is exactly what this run
// would have created: members use the deployment's template, resources,
// repository directory, base packages and setup script, and carry no run
// environment.
func (a *Activities) warmEligible(in CreateSandboxInput, spec sandbox.Spec) bool {
	dir := in.RepositoryDir
	if dir == "" {
		dir = DefaultRepositoryDir
	}
	// A remote member can only fetch a revision by name; an expression the
	// cold full clone could resolve (main~1) must not be claimed and fail.
	if in.LocalPath == "" && !repository.FetchableRevision(in.Revision) {
		return false
	}
	return len(in.Env) == 0 && in.Limits == (sandbox.Limits{}) &&
		spec.Template == a.cfg.SandboxTemplate() && in.Network.AllowInternet != nil &&
		path.Clean(dir) == DefaultRepositoryDir &&
		slices.Equal(in.BasePackages, a.cfg.Sandbox.BasePackages) && in.SetupScript == a.cfg.Sandbox.SetupScript
}

// applyRunPolicy replaces a sandbox's egress policy with the run's.
func (a *Activities) applyRunPolicy(ctx context.Context, sandboxID string, network sandbox.Network) error {
	sb, err := a.provider.Reattach(ctx, sandboxID)
	if err != nil {
		return err
	}
	updater, ok := sb.(sandbox.NetworkUpdater)
	if !ok {
		return errors.New("provider cannot apply the run's egress policy")
	}
	return updater.UpdateNetwork(ctx, network)
}

// recoverWarm completes a claim that a retried CreateSandbox found already
// adopted: the run's policy is applied again (it is idempotent) and the claim
// rebuilt from the labels. The base's lockfile hashes are not in the labels,
// so a configured prepare step re-runs: safe, only slower.
func (a *Activities) recoverWarm(ctx context.Context, info sandbox.Info, network sandbox.Network) (*WarmClaim, error) {
	key, base := info.Metadata[warmPoolLabel], info.Metadata[warmBaseLabel]
	if key == "" {
		return nil, nil
	}
	if err := a.applyRunPolicy(ctx, info.ID, network); err != nil {
		return nil, fmt.Errorf("re-apply the run's egress policy to recovered warm sandbox: %w", err)
	}
	// The claimer died before releasing the entry; the run owns it now.
	if a.warm != nil && validPoolKey(key) {
		_ = a.warm.update(key, func(doc *warmPoolFile) { doc.Members = removeSandbox(doc.Members, info.ID) })
		a.signalWarmRefill()
	}
	return &WarmClaim{PoolKey: key, Base: repository.WarmBase{SHA: base}}, nil
}

// fillWarmPools tops every configured pool up to its size and reaps expired
// members. It fills sequentially: a fill is a sandbox create plus a
// repository preparation, and running them in parallel would only race the
// provider's quota.
func (a *Activities) fillWarmPools(ctx context.Context) error {
	if !a.cfg.Sandbox.Warm.Enabled || a.warm == nil {
		return nil
	}
	var errs []error
	for _, r := range a.cfg.Sandbox.Warm.Repositories {
		// At most size fills per pass: a max_age shorter than a fill would
		// otherwise expire each new member before the next and loop forever.
		for i := 0; i < a.cfg.Sandbox.Warm.size() && ctx.Err() == nil; i++ {
			filled, err := a.fillWarmMember(ctx, r)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", r.source(), err))
				break
			}
			if !filled {
				break
			}
		}
	}
	return errors.Join(errs...)
}

// fillWarmMember adds one ready member to r's pool when it is below size.
func (a *Activities) fillWarmMember(ctx context.Context, r WarmRepository) (bool, error) {
	w := a.cfg.Sandbox.Warm
	key := a.cfg.warmKey(r)
	token := randomToken()
	now := time.Now()
	reserved := false
	var stale []warmMember
	if err := a.warm.update(key, func(doc *warmPoolFile) {
		doc.Source, doc.Ref, doc.Template = r.source(), r.ref(), a.cfg.SandboxTemplate()
		kept := doc.Members[:0]
		for _, m := range doc.Members {
			if expired(m, now, w.maxAge(), w.prepareTimeout()) {
				stale = append(stale, m)
				continue
			}
			kept = append(kept, m)
		}
		doc.Members = kept
		if len(doc.Members) < w.size() {
			doc.Members = append(doc.Members, warmMember{Token: token, State: warmFilling, CreatedAt: now})
			reserved = true
		}
	}); err != nil {
		return false, err
	}
	a.reapWarm(ctx, stale)
	if !reserved {
		return false, nil
	}

	member, err := a.buildWarmMember(ctx, r, key, token)
	if err != nil {
		// Destroy first and forget the entry only once the sandbox is gone;
		// a failed destroy leaves a filling entry that expiry reaps later.
		if a.destroyWarm(ctx, []warmMember{member}, "fill failed") == 0 {
			_ = a.warm.update(key, func(doc *warmPoolFile) { doc.Members = removeToken(doc.Members, token) })
		}
		return false, err
	}
	var kept bool
	if err := a.warm.update(key, func(doc *warmPoolFile) {
		for i := range doc.Members {
			if doc.Members[i].Token == token {
				doc.Members[i] = member
				kept = true
			}
		}
	}); err != nil || !kept {
		// The entry was drained or reaped while filling: the sandbox is
		// nobody's, so it goes.
		a.destroyWarm(ctx, []warmMember{member}, "orphaned fill")
		return false, err
	}
	a.log.InfoContext(ctx, "warm sandbox ready",
		slog.String("pool", key), slog.String("repository.sha", member.Base.SHA),
		slog.Duration("fill", member.FillDuration), slog.Duration("prepare", member.PrepareDuration))
	return true, nil
}

// buildWarmMember creates and prepares one pooled sandbox. The returned
// member carries the sandbox ID as soon as it exists, so a failure can
// destroy it.
func (a *Activities) buildWarmMember(ctx context.Context, r WarmRepository, key, token string) (warmMember, error) {
	w := a.cfg.Sandbox.Warm
	started := time.Now()
	member := warmMember{Token: token, State: warmFilling, CreatedAt: started}
	// Fill-time egress is stated (open), so a credentialed GitHub clone can
	// restore it exactly; the run's own policy replaces it at claim.
	fillNet := sandbox.Network{AllowInternet: boolPointer(true)}
	sb, err := a.provider.Create(ctx, sandbox.Spec{
		Template:    a.cfg.SandboxTemplate(),
		Metadata:    map[string]string{"origin": warmPoolOrigin, "pool": key},
		IdleTimeout: w.maxAge() + w.prepareTimeout() + warmFillSlack,
		Network:     fillNet,
	})
	if err != nil {
		return member, fmt.Errorf("create warm sandbox: %w", err)
	}
	member.SandboxID = sb.ID()
	_ = a.warm.update(key, func(doc *warmPoolFile) {
		for i := range doc.Members {
			if doc.Members[i].Token == token {
				doc.Members[i].SandboxID = sb.ID()
			}
		}
	})

	if err := installBasePackages(ctx, sb, a.cfg.Sandbox.BasePackages, a.log); err != nil {
		return member, err
	}
	if script := strings.TrimSpace(a.cfg.Sandbox.SetupScript); script != "" {
		exec, err := sb.Execute(ctx, sandbox.Command{Script: script, Timeout: w.prepareTimeout(), Description: "operator setup script"})
		if err != nil || !exec.Succeeded() {
			return member, fmt.Errorf("warm setup script failed: %v (exit %d)", err, exec.ExitCode)
		}
	}
	req := r.request(DefaultRepositoryDir)
	var baseline repository.Baseline
	if req.Kind == repository.SourceRemote {
		baseline, err = a.prepareRemoteRepository(ctx, sb, req, fillNet)
	} else {
		baseline, err = a.repos.Prepare(ctx, sb, req)
	}
	if err != nil {
		return member, fmt.Errorf("prepare warm repository: %w", err)
	}
	// A warm member is moved to a run's revision without updating
	// submodules, so a repository with submodules is never pooled.
	if exec, err := sb.Execute(ctx, sandbox.Command{Argv: []string{"test", "-e", DefaultRepositoryDir + "/.gitmodules"}, Description: "check for submodules"}); err != nil {
		return member, err
	} else if exec.ExitCode == 0 {
		return member, fmt.Errorf("%s has submodules, which the warm pool does not move between revisions", r.source())
	}
	prepare, err := a.runWarmPrepare(ctx, sb, DefaultRepositoryDir)
	if err != nil {
		return member, err
	}
	if err := checkWarmHasNoSecrets(ctx, sb, DefaultRepositoryDir); err != nil {
		return member, err
	}
	member.State = warmReady
	member.Base = repository.WarmBase{SHA: baseline.SHA, LockfileHashes: baseline.LockfileHashes}
	member.ReadyAt = time.Now()
	member.FillDuration = member.ReadyAt.Sub(started)
	member.PrepareDuration = prepare
	return member, nil
}

// runWarmPrepare runs the configured prepare command in the repository.
func (a *Activities) runWarmPrepare(ctx context.Context, sb sandbox.Sandbox, dest string) (time.Duration, error) {
	argv := a.cfg.Sandbox.Warm.PrepareCommand
	if len(argv) == 0 {
		return 0, nil
	}
	started := time.Now()
	exec, err := sb.Execute(ctx, sandbox.Command{Argv: argv, Dir: dest, Timeout: a.cfg.Sandbox.Warm.prepareTimeout(), Description: "warm prepare command"})
	if err != nil {
		return 0, fmt.Errorf("prepare command: %w", err)
	}
	if !exec.Succeeded() {
		return 0, fmt.Errorf("prepare command failed (exit %d): %s", exec.ExitCode, truncateForError(exec.Stderr, 400))
	}
	return time.Since(started), nil
}

// warmSecretCheck refuses a member whose repository could authenticate on
// its own: a credential helper, an extra auth header, credentials in a
// remote URL, or a stored credentials file. Tokens stay at the proxy.
const warmSecretCheck = `set -u
d="$1"
found=""
if git -C "$d" config --get-regexp '^(credential\.|http\..*extraheader)' >/dev/null 2>&1; then found="$found git-credential-config"; fi
if git -C "$d" remote -v 2>/dev/null | grep -Eq '://[^/ ]*@'; then found="$found remote-url-credentials"; fi
for f in "$HOME/.git-credentials" "$HOME/.netrc" "$HOME/.npmrc" "$d/.git-credentials"; do
  if [ -s "$f" ] && grep -Eqi '(password|_authToken|x-access-token|://[^/ ]*@)' "$f" 2>/dev/null; then found="$found $f"; fi
done
if [ -n "$found" ]; then echo "warm sandbox holds credentials:$found" >&2; exit 1; fi
`

func checkWarmHasNoSecrets(ctx context.Context, sb sandbox.Sandbox, dest string) error {
	exec, err := sb.Execute(ctx, sandbox.Command{Argv: []string{"sh", "-c", warmSecretCheck, "warm-secret-check", dest}, Description: "warm secret check"})
	if err != nil {
		return fmt.Errorf("warm secret check: %w", err)
	}
	if !exec.Succeeded() {
		return fmt.Errorf("refusing warm sandbox: %s", strings.TrimSpace(exec.Stderr))
	}
	return nil
}

// drainWarmPools destroys every pooled sandbox of this deployment and
// empties its pools. A member mid-claim is left to its claimer.
func (a *Activities) drainWarmPools(ctx context.Context) (int, error) {
	if a.warm == nil {
		return 0, nil
	}
	keys := map[string]bool{}
	for _, r := range a.cfg.Sandbox.Warm.Repositories {
		keys[a.cfg.warmKey(r)] = true
	}
	entries, err := os.ReadDir(a.warm.root)
	if err != nil {
		return 0, err
	}
	destroyed := map[string]bool{}
	claiming := map[string]bool{}
	var abandoned []warmMember
	for _, e := range entries {
		key, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok {
			continue
		}
		keys[key] = true
		var members []warmMember
		if err := a.warm.update(key, func(doc *warmPoolFile) {
			kept := doc.Members[:0]
			for _, m := range doc.Members {
				if m.State == warmClaiming {
					// A claim may already be a run's sandbox: never destroyed
					// here. An abandoned one is reaped with a label check.
					claiming[m.SandboxID] = true
					if expired(m, time.Now(), 0, 0) {
						abandoned = append(abandoned, m)
						continue
					}
					kept = append(kept, m)
					continue
				}
				members = append(members, m)
			}
			doc.Members = kept
		}); err != nil {
			return len(destroyed), err
		}
		for _, m := range members {
			if m.SandboxID != "" && !destroyed[m.SandboxID] && a.destroyWarm(ctx, []warmMember{m}, "drained") == 0 {
				destroyed[m.SandboxID] = true
			}
		}
	}
	a.reapWarm(ctx, abandoned)
	// Members whose record was lost: only this deployment's pools, never a
	// sandbox mid-claim, and never one already counted.
	if infos, err := a.provider.List(ctx); err == nil {
		for _, info := range infos {
			if info.Metadata["origin"] != warmPoolOrigin || !keys[info.Metadata["pool"]] || claiming[info.ID] || destroyed[info.ID] {
				continue
			}
			if a.destroyWarm(ctx, []warmMember{{SandboxID: info.ID}}, "unrecorded") == 0 {
				destroyed[info.ID] = true
			}
		}
	}
	return len(destroyed), nil
}

// WarmPoolStatus summarises each pool for operators.
type WarmPoolStatus struct {
	Key      string `json:"key"`
	Source   string `json:"source"`
	Ref      string `json:"ref"`
	Ready    int    `json:"ready"`
	Filling  int    `json:"filling"`
	Claiming int    `json:"claiming"`
}

// warmPools reports the configured pools. It only reads: documents are
// replaced by atomic rename, so an unlocked read sees a whole one.
func (a *Activities) warmPools() ([]WarmPoolStatus, error) {
	var out []WarmPoolStatus
	for _, r := range a.cfg.Sandbox.Warm.Repositories {
		st := WarmPoolStatus{Key: a.cfg.warmKey(r), Source: r.source(), Ref: r.ref()}
		if a.warm != nil {
			doc, err := a.warm.load(st.Key)
			if err != nil {
				return nil, err
			}
			for _, m := range doc.Members {
				switch m.State {
				case warmReady:
					st.Ready++
				case warmClaiming:
					st.Claiming++
				default:
					st.Filling++
				}
			}
		}
		out = append(out, st)
	}
	return out, nil
}

// destroyWarm destroys members and returns how many could not be destroyed.
func (a *Activities) destroyWarm(ctx context.Context, members []warmMember, reason string) int {
	failed := 0
	for _, m := range members {
		if m.SandboxID == "" {
			continue
		}
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Minute)
		if err := a.provider.Destroy(dctx, m.SandboxID); err != nil {
			failed++
			a.log.WarnContext(ctx, "warm sandbox destroy failed", slog.String("sandbox.id", m.SandboxID), slog.String("reason", reason), slog.Any("error", err))
		}
		cancel()
	}
	return failed
}

// reapWarm destroys expired members. An expired claim may have been adopted
// before its claimer died; a sandbox that already carries a run's ownership
// is that run's to clean up, so only still pool-labelled ones go.
func (a *Activities) reapWarm(ctx context.Context, members []warmMember) {
	var claims, rest []warmMember
	for _, m := range members {
		if m.State == warmClaiming {
			claims = append(claims, m)
		} else {
			rest = append(rest, m)
		}
	}
	a.destroyWarm(ctx, rest, "expired")
	if len(claims) == 0 {
		return
	}
	infos, err := a.provider.List(ctx)
	if err != nil {
		return
	}
	for _, m := range claims {
		for _, info := range infos {
			if info.ID == m.SandboxID && info.Metadata["origin"] == warmPoolOrigin {
				a.destroyWarm(ctx, []warmMember{m}, "abandoned claim")
			}
		}
	}
}

// signalWarmRefill asks the worker's refill loop to top the pools up now,
// without blocking when a refill is already pending.
func (a *Activities) signalWarmRefill() {
	if a.warmRefill == nil {
		return
	}
	select {
	case a.warmRefill <- struct{}{}:
	default:
	}
}

// runWarmPool keeps the pools filled until ctx ends: at start, after every
// claim, and at least every interval.
func (a *Activities) runWarmPool(ctx context.Context, interval time.Duration) {
	if !a.cfg.Sandbox.Warm.Enabled || a.warm == nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := a.fillWarmPools(ctx); err != nil && ctx.Err() == nil {
			a.log.WarnContext(ctx, "warm pool refill failed", slog.Any("error", err))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-a.warmRefill:
		}
	}
}

func removeSandbox(members []warmMember, id string) []warmMember {
	return slices.DeleteFunc(members, func(m warmMember) bool { return m.SandboxID == id })
}

func removeToken(members []warmMember, token string) []warmMember {
	return slices.DeleteFunc(members, func(m warmMember) bool { return m.Token == token })
}

func randomToken() string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

// Preparation is the run's evidence of how its sandbox and repository were
// prepared (preparation.json), for both paths, so warm and cold runs can be
// compared from evidence alone.
type Preparation struct {
	// Path is "warm" or "cold".
	Path               string        `json:"path"`
	AcquireDuration    time.Duration `json:"acquire_duration"`
	RepositoryDuration time.Duration `json:"repository_duration"`
	// TransferredBytes is what was moved into the sandbox for the revision.
	TransferredBytes int64      `json:"transferred_bytes,omitempty"`
	Warm             *WarmClaim `json:"warm,omitempty"`
	// PrepareRerun records that lockfiles changed since the warm base, so the
	// prepare command ran again for this revision.
	PrepareRerun    bool          `json:"prepare_rerun,omitempty"`
	PrepareDuration time.Duration `json:"prepare_duration,omitempty"`
}

// updateWarmRepository moves a claimed sandbox's repository from the pool's
// base to the requested revision, and re-runs the prepare step only when a
// dependency lockfile changed. The prepare step then runs under the run's
// egress policy, which the claim already applied: a policy that blocks the
// package registry fails the run with that reason rather than loosening it.
func (a *Activities) updateWarmRepository(ctx context.Context, sb sandbox.Sandbox, req repository.Request, network sandbox.Network, claim *WarmClaim, ev *Preparation) (repository.Baseline, error) {
	update := func(r repository.Request) (repository.Baseline, error) {
		return a.repos.Update(ctx, sb, r, claim.Base)
	}
	var baseline repository.Baseline
	var err error
	if req.Kind == repository.SourceRemote {
		baseline, err = a.withRepositoryCredential(ctx, sb, req, network, update)
	} else {
		baseline, err = update(req)
	}
	if err != nil {
		return repository.Baseline{}, err
	}
	if len(a.cfg.Sandbox.Warm.PrepareCommand) > 0 && !maps.Equal(baseline.LockfileHashes, claim.Base.LockfileHashes) {
		d, err := a.runWarmPrepare(ctx, sb, req.DestDir)
		if err != nil {
			return repository.Baseline{}, fmt.Errorf("dependency lockfiles changed since the warm base and the prepare step failed under the run's egress policy: %w", err)
		}
		ev.PrepareRerun, ev.PrepareDuration = true, d
	}
	return baseline, nil
}

// WarmPoolService is the operator and worker interface to the warm pool. It
// is a separate type because every exported method of Activities is
// registered as a Temporal activity.
type WarmPoolService struct{ a *Activities }

// NewWarmPoolService returns the pool service for a set of activities.
func NewWarmPoolService(a *Activities) WarmPoolService { return WarmPoolService{a: a} }

// Run keeps the pools filled until ctx ends.
func (s WarmPoolService) Run(ctx context.Context, interval time.Duration) {
	s.a.runWarmPool(ctx, interval)
}

// Fill tops every pool up once.
func (s WarmPoolService) Fill(ctx context.Context) error { return s.a.fillWarmPools(ctx) }

// Drain destroys every pooled sandbox and reports how many.
func (s WarmPoolService) Drain(ctx context.Context) (int, error) { return s.a.drainWarmPools(ctx) }

// Status summarises the pools.
func (s WarmPoolService) Status() ([]WarmPoolStatus, error) { return s.a.warmPools() }
