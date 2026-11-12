package baseten

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mitkox/esf/internal/sandbox"
)

const (
	// singleUploadBytes is the largest file sent in one request; larger files
	// use the multipart upload API in parts of this size.
	singleUploadBytes = 5 << 20
	// timeoutGrace lets the server-side process timeout fire before the
	// client gives up, so a timed-out command is reported, not abandoned.
	timeoutGrace = 15 * time.Second
	// maxPollFailures tolerates transient data-plane errors while a long
	// command runs, without hiding a sandbox that is really gone.
	maxPollFailures = 5
	maxPollInterval = 2 * time.Second
	// killTimeout bounds the best-effort kill of an abandoned command.
	killTimeout = 15 * time.Second

	// maxCommandDuration bounds a command that has no timeout and no
	// deadline. It is a leak backstop, far above any factory timeout.
	maxCommandDuration = 24 * time.Hour

	processRunning = "running"
	processKilled  = "killed"
)

// processFinished lists the terminal process states. Anything else that is
// not "running" is an error: treating an unknown state as finished would
// report a command that never ran as a success.
var processFinished = map[string]bool{"completed": true, "failed": true, "killed": true, "stopped": true}

// basetenSandbox adapts one Baseten sandbox to sandbox.Sandbox and
// sandbox.NetworkUpdater.
type basetenSandbox struct {
	provider    *Provider
	id          string
	template    string
	dataPlane   string
	outputLimit int64
}

func (s *basetenSandbox) ID() string       { return s.id }
func (s *basetenSandbox) Template() string { return s.template }

// UpdateNetwork replaces the live sandbox's egress policy and verifies the
// platform reports it in effect.
func (s *basetenSandbox) UpdateNetwork(ctx context.Context, network sandbox.Network) error {
	if err := s.provider.updateNetwork(ctx, s.id, network); err != nil {
		return fmt.Errorf("update network for sandbox %s: %w", s.id, err)
	}
	return nil
}

// processState is the data plane's view of one process.
type processState struct {
	Status   string `json:"status"`
	ExitCode int    `json:"exitCode"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

// Execute runs one command and waits for it.
//
// The command is started detached and then polled, rather than held open on
// one request: agent runs last tens of minutes, longer than intermediaries
// reliably keep a single HTTP request alive. keepAlive stops the sandbox
// from scaling to zero while the command runs.
//
// Argv is rendered through sandbox.CommandLine, which single-quotes every
// element, and the line is wrapped by sandbox.BoundedCommandScript so output
// is capped inside the VM. A non-zero exit is a result, not an error.
func (s *basetenSandbox) Execute(ctx context.Context, cmd sandbox.Command) (sandbox.Execution, error) {
	line, err := sandbox.CommandLine(cmd)
	if err != nil {
		return sandbox.Execution{}, err
	}
	name, err := randomName()
	if err != nil {
		return sandbox.Execution{}, err
	}
	// keepAlive stops standby, so the server-side timeout is the only thing
	// that ends a command the worker abandons (a crash, a lost workflow).
	// It is always sent: the command's own timeout, else the caller's
	// deadline, else maxCommandDuration.
	timeout := cmd.Timeout
	if timeout <= 0 {
		timeout = maxCommandDuration
		if deadline, ok := ctx.Deadline(); ok {
			timeout = time.Until(deadline)
		}
	}
	body := map[string]any{
		"command":           sandbox.BoundedCommandScript(line, s.outputLimit),
		"name":              name,
		"waitForCompletion": false,
		"keepAlive":         true,
		"timeout":           ceilSeconds(timeout),
	}
	if cmd.Dir != "" {
		body["workingDir"] = cmd.Dir
	}
	if len(cmd.Env) > 0 {
		body["env"] = cmd.Env
	}

	started := time.Now().UTC()
	finish := func(st processState, timedOut bool, note string) sandbox.Execution {
		done := time.Now().UTC()
		exec := sandbox.Execution{
			ExitCode: st.ExitCode, Stdout: st.Stdout, Stderr: st.Stderr,
			StartedAt: started, CompletedAt: done, Duration: done.Sub(started), TimedOut: timedOut,
		}
		if timedOut || note != "" {
			exec.ExitCode = -1
			if note != "" {
				exec.Stderr = strings.TrimSpace(exec.Stderr + "\n" + note)
			}
		}
		return exec
	}

	if err := s.provider.api.doJSON(ctx, request{Method: http.MethodPost, URL: s.dataPlane + "/process", Op: "start process"}, body, nil); err != nil {
		if ctx.Err() != nil {
			// The start may have reached the sandbox before the context ended.
			s.kill(name)
			return finish(processState{}, errors.Is(ctx.Err(), context.DeadlineExceeded), contextNote(ctx)), nil
		}
		return sandbox.Execution{}, fmt.Errorf("execute in sandbox %s: %w", s.id, classify(err))
	}

	var deadline time.Time
	if cmd.Timeout > 0 {
		deadline = started.Add(cmd.Timeout + timeoutGrace)
	}
	// Each poll returns the process's stdout and stderr, but those stay empty
	// while it runs: BoundedCommandScript sends the command's streams to files
	// and prints them only on exit. Polling a long run is status-sized.
	interval := s.provider.poll / 4
	failures := 0
	for {
		var st processState
		err := s.provider.api.doJSON(ctx, request{Method: http.MethodGet, URL: s.dataPlane + "/process/" + url.PathEscape(name), Op: "poll process"}, nil, &st)
		switch {
		case ctx.Err() != nil:
			s.kill(name)
			return finish(st, errors.Is(ctx.Err(), context.DeadlineExceeded), contextNote(ctx)), nil
		case err != nil:
			classified := classify(err)
			if !errors.Is(classified, ErrUnavailable) || failures >= maxPollFailures {
				return sandbox.Execution{}, fmt.Errorf("execute in sandbox %s: %w", s.id, classified)
			}
			failures++
		case processFinished[st.Status]:
			// The server enforces cmd.Timeout and reports the process killed.
			return finish(st, cmd.Timeout > 0 && st.Status == processKilled, ""), nil
		case st.Status != processRunning:
			s.kill(name)
			return sandbox.Execution{}, fmt.Errorf("%w: execute in sandbox %s: unknown process status %q", ErrUnavailable, s.id, st.Status)
		default:
			failures = 0
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			s.kill(name)
			return finish(st, true, "command timed out"), nil
		}
		if sleep(ctx, interval) != nil {
			continue // the next iteration observes ctx and kills
		}
		if interval < maxPollInterval {
			interval *= 2
		}
	}
}

// kill stops an abandoned command. It is best effort and uses a fresh
// context, because the caller's is usually what expired.
func (s *basetenSandbox) kill(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), killTimeout)
	defer cancel()
	err := s.provider.api.doJSON(ctx, request{Method: http.MethodDelete, URL: s.dataPlane + "/process/" + url.PathEscape(name) + "/kill", Op: "kill process"}, nil, nil)
	if err != nil && !isNotFound(err) {
		s.provider.log.Warn("baseten process kill failed", slog.String("sandbox.id", s.id), slog.Any("error", err))
	}
}

// WriteFile writes data at an absolute path, creating parent directories.
// Large files use the multipart upload API so no single request exceeds the
// data plane's body limit.
func (s *basetenSandbox) WriteFile(ctx context.Context, path string, data []byte) error {
	target, err := filePath(path)
	if err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	if len(data) <= singleUploadBytes {
		form, contentType, err := fileForm(data, map[string]string{"permissions": "0644"})
		if err != nil {
			return err
		}
		err = s.provider.api.doJSON(ctx, request{Method: http.MethodPut, URL: s.dataPlane + "/filesystem/" + target, Body: form, ContentType: contentType, Op: "write file", Timeout: -1}, nil, nil)
		if err != nil {
			return fmt.Errorf("write %s in sandbox %s: %w", path, s.id, classify(err))
		}
		return nil
	}
	if err := s.writeMultipart(ctx, target, bytes.NewReader(data), int64(len(data))); err != nil {
		return fmt.Errorf("write %s in sandbox %s: %w", path, s.id, err)
	}
	return nil
}

// WriteFileFrom streams size bytes from r into the sandbox. At most one
// upload part (5 MiB) is held in memory, so a large repository snapshot does
// not have to fit in the worker's heap.
func (s *basetenSandbox) WriteFileFrom(ctx context.Context, path string, r io.Reader, size int64) error {
	if size < 0 {
		return fmt.Errorf("write file: negative size")
	}
	if size <= singleUploadBytes {
		data := make([]byte, size)
		if _, err := io.ReadFull(r, data); err != nil {
			return fmt.Errorf("write %s in sandbox %s: read source: %w", path, s.id, err)
		}
		return s.WriteFile(ctx, path, data)
	}
	target, err := filePath(path)
	if err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	if err := s.writeMultipart(ctx, target, r, size); err != nil {
		return fmt.Errorf("write %s in sandbox %s: %w", path, s.id, err)
	}
	return nil
}

func (s *basetenSandbox) writeMultipart(ctx context.Context, target string, r io.Reader, size int64) error {
	api := s.provider.api
	var initiated struct {
		UploadID string `json:"uploadId"`
	}
	if err := api.doJSON(ctx, request{Method: http.MethodPost, URL: s.dataPlane + "/filesystem-multipart/initiate/" + target, Op: "initiate upload"},
		map[string]string{"permissions": "0644"}, &initiated); err != nil {
		return classify(err)
	}
	if initiated.UploadID == "" {
		return fmt.Errorf("%w: upload was not assigned an id", ErrUnavailable)
	}
	uploadURL := s.dataPlane + "/filesystem-multipart/" + url.PathEscape(initiated.UploadID)
	completed := false
	defer func() {
		if !completed {
			abortCtx, cancel := context.WithTimeout(context.Background(), killTimeout)
			defer cancel()
			_ = api.doJSON(abortCtx, request{Method: http.MethodDelete, URL: uploadURL + "/abort", Op: "abort upload"}, nil, nil)
		}
	}()
	type part struct {
		ETag       string `json:"etag"`
		PartNumber int    `json:"partNumber"`
	}
	var parts []part
	chunk := make([]byte, singleUploadBytes)
	for offset, number := int64(0), 1; offset < size; offset, number = offset+singleUploadBytes, number+1 {
		n := min(int64(singleUploadBytes), size-offset)
		if _, err := io.ReadFull(r, chunk[:n]); err != nil {
			return fmt.Errorf("read source at byte %d: %w", offset, err)
		}
		form, contentType, err := fileForm(chunk[:n], nil)
		if err != nil {
			return err
		}
		var uploaded part
		if err := api.doJSON(ctx, request{Method: http.MethodPut, URL: uploadURL + "/part?partNumber=" + strconv.Itoa(number), Body: form, ContentType: contentType, Op: "upload part", Timeout: -1}, nil, &uploaded); err != nil {
			return classify(err)
		}
		if uploaded.PartNumber == 0 {
			uploaded.PartNumber = number
		}
		parts = append(parts, uploaded)
	}
	if err := api.doJSON(ctx, request{Method: http.MethodPost, URL: uploadURL + "/complete", Op: "complete upload"}, map[string]any{"parts": parts}, nil); err != nil {
		return classify(err)
	}
	completed = true
	return nil
}

// ReadFile reads a file's raw bytes.
func (s *basetenSandbox) ReadFile(ctx context.Context, path string) ([]byte, error) {
	target, err := filePath(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	resp, cancel, err := s.provider.api.do(ctx, request{Method: http.MethodGet, URL: s.dataPlane + "/filesystem/" + target + "?download=true", Op: "read file", Timeout: -1})
	if err != nil {
		return nil, fmt.Errorf("read %s in sandbox %s: %w", path, s.id, classify(err))
	}
	defer cancel()
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, DefaultMaxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read %s in sandbox %s: %v", ErrUnavailable, path, s.id, err)
	}
	if int64(len(data)) > DefaultMaxFileBytes {
		return nil, fmt.Errorf("read %s in sandbox %s: file exceeds %d bytes", path, s.id, DefaultMaxFileBytes)
	}
	return data, nil
}

// Destroy terminates this sandbox. It is idempotent.
func (s *basetenSandbox) Destroy(ctx context.Context) error {
	return s.provider.Destroy(ctx, s.id)
}

// filePath renders an absolute sandbox path for the filesystem API, which
// treats a path without a leading slash as relative to its working directory.
// The leading slash is kept, so the URL reads /filesystem//abs/path.
func filePath(path string) (string, error) {
	if !strings.HasPrefix(path, "/") || path == "/" {
		return "", fmt.Errorf("path %q must be an absolute file path", path)
	}
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		if segment == "." || segment == ".." {
			return "", fmt.Errorf("path %q must not contain . or .. segments", path)
		}
		segments[i] = url.PathEscape(segment)
	}
	return strings.Join(segments, "/"), nil
}

// fileForm builds the multipart/form-data body the data plane expects for
// binary content.
func fileForm(data []byte, fields map[string]string) ([]byte, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			return nil, "", err
		}
	}
	fw, err := w.CreateFormFile("file", "upload.bin")
	if err != nil {
		return nil, "", err
	}
	if _, err := fw.Write(data); err != nil {
		return nil, "", err
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), w.FormDataContentType(), nil
}

func ceilSeconds(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64((d + time.Second - 1) / time.Second)
}

func contextNote(ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "command timed out"
	}
	return "command cancelled"
}
