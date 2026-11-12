package baseten

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testAPIKey = "test-baseten-key"

// fakeBaseten emulates the three surfaces the provider talks to: Baseten's
// token endpoint, Blaxel's control plane, and one sandbox data plane. It is
// deliberately strict about authentication so a test cannot pass while the
// provider sends the wrong credential to the wrong place.
type fakeBaseten struct {
	t   *testing.T
	srv *httptest.Server

	mu         sync.Mutex
	tokens     int
	sandboxes  map[string]map[string]any
	requests   []string
	bodies     map[string][]byte
	processes  map[string]map[string]any
	files      map[string][]byte
	uploads    map[string][][]byte
	killed     []string
	aborted    int
	listPages  bool
	deleteWait int // GETs reporting DELETING before TERMINATED

	// Hooks let a test change behaviour without re-implementing routes.
	onCreate     func(body map[string]any) (status string, network map[string]any)
	processAfter func(name string, polls int) map[string]any
	rejectToken  bool
	pollFailures int
	// missingGets makes the next sandbox GETs 404, like a control plane
	// that has not caught up with its own create.
	missingGets int
	tokenDelay  time.Duration
	// getFailures makes the next sandbox GETs answer 503.
	getFailures int
	listQueries []string
	failPart    bool
	regions     []map[string]any
	workspaces  []string
}

func newFake(t *testing.T) *fakeBaseten {
	f := &fakeBaseten{
		t:          t,
		sandboxes:  map[string]map[string]any{},
		bodies:     map[string][]byte{},
		processes:  map[string]map[string]any{},
		files:      map[string][]byte{},
		uploads:    map[string][][]byte{},
		regions:    []map[string]any{{"name": "us-pdx-1", "proxyAvailable": true}},
		workspaces: []string{"baseten-team"},
	}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeBaseten) token() string {
	claims, _ := json.Marshal(map[string]any{"exp": time.Now().Add(2 * time.Hour).Unix()})
	return "h." + base64.RawURLEncoding.EncodeToString(claims) + fmt.Sprintf(".sig%d", f.tokens)
}

func (f *fakeBaseten) provider(t *testing.T, mutate ...func(*Config)) *Provider {
	t.Helper()
	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, []byte(testAPIKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		APIKeyFile:      keyFile,
		APIURL:          f.srv.URL,
		ControlPlaneURL: f.srv.URL + "/v0",
		Region:          "us-pdx-1",
		Template:        "blaxel/claude-code:latest",
	}
	for _, m := range mutate {
		m(&cfg)
	}
	p, err := New(cfg, WithHTTPClient(f.srv.Client()), withPollInterval(time.Millisecond))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func (f *fakeBaseten) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	key := r.Method + " " + r.URL.EscapedPath()
	f.requests = append(f.requests, key)
	f.bodies[key] = body

	if r.URL.Path == "/v1/token" {
		if f.tokenDelay > 0 {
			f.mu.Unlock()
			select {
			case <-time.After(f.tokenDelay):
			case <-r.Context().Done():
			}
			f.mu.Lock()
		}
		if r.Header.Get("Authorization") != "Bearer "+testAPIKey || f.rejectToken {
			writeJSON(w, 401, map[string]any{"code": "UNAUTHORIZED"})
			return
		}
		f.tokens++
		writeJSON(w, 200, map[string]any{"token": f.token()})
		return
	}
	// Everything else must carry a minted token, never the API key.
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer h.") {
		writeJSON(w, 401, map[string]any{"error": "Unauthorized"})
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v0/") && r.URL.Path != "/v0/workspaces" && r.Header.Get("X-Blaxel-Workspace") == "" {
		writeJSON(w, 403, map[string]any{"error": "workspace required"})
		return
	}

	path := r.URL.Path
	switch {
	case path == "/v0/workspaces":
		var out []map[string]any
		for _, ws := range f.workspaces {
			out = append(out, map[string]any{"name": ws})
		}
		writeJSON(w, 200, out)
	case path == "/v0/configuration":
		writeJSON(w, 200, map[string]any{"regions": f.regions})
	case path == "/v0/sandboxes" && r.Method == http.MethodPost:
		f.create(w, body)
	case path == "/v0/sandboxes" && r.Method == http.MethodGet:
		f.listQueries = append(f.listQueries, r.URL.RawQuery)
		f.list(w, r)
	case strings.HasPrefix(path, "/v0/sandboxes/"):
		f.sandbox(w, r, strings.TrimPrefix(path, "/v0/sandboxes/"), body)
	case path == "/data/process" && r.Method == http.MethodPost:
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		name := req["name"].(string)
		f.processes[name] = map[string]any{"status": "running", "polls": 0, "request": req}
		writeJSON(w, 200, map[string]any{"name": name, "status": "running"})
	case strings.HasPrefix(path, "/data/process/") && strings.HasSuffix(path, "/kill"):
		name := strings.TrimSuffix(strings.TrimPrefix(path, "/data/process/"), "/kill")
		f.killed = append(f.killed, name)
		writeJSON(w, 200, map[string]any{})
	case strings.HasPrefix(path, "/data/process/"):
		name := strings.TrimPrefix(path, "/data/process/")
		p := f.processes[name]
		if p == nil {
			writeJSON(w, 404, map[string]any{"error": "no such process"})
			return
		}
		if f.pollFailures > 0 {
			f.pollFailures--
			writeJSON(w, 503, map[string]any{"error": "data plane restarting"})
			return
		}
		p["polls"] = p["polls"].(int) + 1
		state := map[string]any{"status": "completed", "exitCode": 0, "stdout": "ok\n", "stderr": ""}
		if f.processAfter != nil {
			state = f.processAfter(name, p["polls"].(int))
		}
		writeJSON(w, 200, state)
	case strings.HasPrefix(r.URL.EscapedPath(), "/data/filesystem/"):
		f.filesystem(w, r, body)
	case strings.HasPrefix(path, "/data/filesystem-multipart/"):
		f.multipart(w, r, body)
	default:
		writeJSON(w, 404, map[string]any{"error": "route " + key})
	}
}

func (f *fakeBaseten) create(w http.ResponseWriter, body []byte) {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad json"})
		return
	}
	meta := req["metadata"].(map[string]any)
	spec := req["spec"].(map[string]any)
	name := meta["name"].(string)
	status := "DEPLOYING"
	if f.onCreate != nil {
		var network map[string]any
		status, network = f.onCreate(req)
		if network != nil {
			spec["network"] = network
		}
	}
	meta["url"] = f.srv.URL + "/data"
	meta["createdAt"] = "2026-11-12T08:43:20.383180626Z"
	sb := map[string]any{"metadata": meta, "spec": spec, "status": status, "polls": 0}
	f.sandboxes[name] = sb
	// Like the real API, the create response echoes the request, secrets
	// included.
	writeJSON(w, 200, sb)
}

func (f *fakeBaseten) list(w http.ResponseWriter, r *http.Request) {
	var items []map[string]any
	for _, sb := range f.sandboxes {
		items = append(items, sb)
	}
	if !f.listPages {
		writeJSON(w, 200, items)
		return
	}
	// Paged shape, one item per page.
	cursor := r.URL.Query().Get("cursor")
	idx := 0
	if cursor != "" {
		fmt.Sscanf(cursor, "c%d", &idx)
	}
	page := map[string]any{"data": []any{}, "meta": map[string]any{}}
	if idx < len(items) {
		page["data"] = []any{items[idx]}
		if idx+1 < len(items) {
			page["meta"] = map[string]any{"nextCursor": fmt.Sprintf("c%d", idx+1)}
		}
	}
	writeJSON(w, 200, page)
}

func (f *fakeBaseten) sandbox(w http.ResponseWriter, r *http.Request, name string, body []byte) {
	sb := f.sandboxes[name]
	if r.Method == http.MethodGet && f.getFailures > 0 {
		f.getFailures--
		writeJSON(w, 503, map[string]any{"error": "control plane busy"})
		return
	}
	if r.Method == http.MethodGet && f.missingGets > 0 {
		f.missingGets--
		sb = nil
	}
	if sb == nil {
		writeJSON(w, 404, map[string]any{"error": "sandbox not found"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		switch sb["status"] {
		case "DEPLOYING":
			sb["polls"] = sb["polls"].(int) + 1
			if sb["polls"].(int) >= 2 {
				sb["status"] = "DEPLOYED"
			}
		case "DELETING":
			if f.deleteWait <= 0 {
				sb["status"] = "TERMINATED"
			}
			f.deleteWait--
		}
		writeJSON(w, 200, stripSecrets(sb))
	case http.MethodDelete:
		sb["status"] = "DELETING"
		writeJSON(w, 200, sb)
	case http.MethodPut:
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		sb["spec"] = req["spec"]
		writeJSON(w, 200, sb)
	}
}

func (f *fakeBaseten) filesystem(w http.ResponseWriter, r *http.Request, body []byte) {
	path := strings.TrimPrefix(r.URL.EscapedPath(), "/data/filesystem/")
	switch r.Method {
	case http.MethodPut:
		data, ok := formFile(r, body)
		if !ok {
			writeJSON(w, 400, map[string]any{"error": "expected multipart form"})
			return
		}
		f.files[path] = data
		writeJSON(w, 200, map[string]any{"message": "ok"})
	case http.MethodGet:
		if r.URL.Query().Get("download") != "true" {
			writeJSON(w, 400, map[string]any{"error": "download expected"})
			return
		}
		data, ok := f.files[path]
		if !ok {
			writeJSON(w, 404, map[string]any{"error": "stat " + path + ": no such file or directory"})
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(data)
	}
}

func (f *fakeBaseten) multipart(w http.ResponseWriter, r *http.Request, body []byte) {
	rest := strings.TrimPrefix(r.URL.EscapedPath(), "/data/filesystem-multipart/")
	switch {
	case strings.HasPrefix(rest, "initiate/"):
		id := fmt.Sprintf("up%d", len(f.uploads))
		f.uploads[id] = nil
		f.files["pending:"+id] = []byte(strings.TrimPrefix(rest, "initiate/"))
		writeJSON(w, 200, map[string]any{"uploadId": id})
	case strings.HasSuffix(rest, "/part"):
		id := strings.TrimSuffix(rest, "/part")
		if f.failPart && len(f.uploads[id]) == 1 {
			writeJSON(w, 500, map[string]any{"error": "boom"})
			return
		}
		data, _ := formFile(r, body)
		f.uploads[id] = append(f.uploads[id], data)
		writeJSON(w, 200, map[string]any{"etag": "e" + r.URL.Query().Get("partNumber"), "partNumber": len(f.uploads[id])})
	case strings.HasSuffix(rest, "/complete"):
		id := strings.TrimSuffix(rest, "/complete")
		var joined []byte
		for _, part := range f.uploads[id] {
			joined = append(joined, part...)
		}
		f.files[string(f.files["pending:"+id])] = joined
		writeJSON(w, 200, map[string]any{"message": "ok"})
	case strings.HasSuffix(rest, "/abort"):
		f.aborted++
		writeJSON(w, 200, map[string]any{})
	}
}

func formFile(r *http.Request, body []byte) ([]byte, bool) {
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		return nil, false
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		return nil, false
	}
	data, _ := io.ReadAll(file)
	return data, true
}

func stripSecrets(sb map[string]any) map[string]any {
	raw, _ := json.Marshal(sb)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if spec, ok := out["spec"].(map[string]any); ok {
		if network, ok := spec["network"].(map[string]any); ok {
			if proxy, ok := network["proxy"].(map[string]any); ok {
				if routes, ok := proxy["routing"].([]any); ok {
					for _, route := range routes {
						delete(route.(map[string]any), "secrets")
					}
				}
			}
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeBaseten) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

func (f *fakeBaseten) body(key string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out map[string]any
	_ = json.Unmarshal(f.bodies[key], &out)
	return out
}

func fakeResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}
}
