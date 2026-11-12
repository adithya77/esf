package baseten

import (
	"errors"
	"reflect"
	"testing"

	"github.com/mitkox/esf/internal/sandbox"
)

func boolPtr(b bool) *bool { return &b }

func TestTranslateNetworkPostures(t *testing.T) {
	cases := []struct {
		name          string
		in            sandbox.Network
		wantAllowed   []string
		wantForbidden []string
	}{
		{"deployment default is open", sandbox.Network{}, []string{"*"}, nil},
		{"explicitly open", sandbox.Network{AllowInternet: boolPtr(true), AllowOut: []string{"ignored.example"}}, []string{"*"}, nil},
		// "*" is not sent alongside a denylist, so precedence never matters.
		{"open with deny", sandbox.Network{DenyOut: []string{"evil.example", "*.bad.example"}}, nil, []string{"evil.example", "*.bad.example"}},
		// An empty allowlist would mean "allow all"; deny-all must forbid "*".
		{"closed, nothing allowed", sandbox.Network{AllowInternet: boolPtr(false)}, nil, []string{"*"}},
		{"closed allowlist", sandbox.Network{AllowInternet: boolPtr(false), AllowOut: []string{"GitHub.com", "*.pypi.org"}}, []string{"github.com", "*.pypi.org"}, nil},
		{"closed allowlist with deny", sandbox.Network{AllowInternet: boolPtr(false), AllowOut: []string{"*.example.com"}, DenyOut: []string{"www.example.com"}}, []string{"*.example.com"}, []string{"www.example.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := translateNetwork(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if !got.enforced() {
				t.Fatal("every policy must carry the proxy firewall")
			}
			if !reflect.DeepEqual(nilIfEmpty(got.Proxy.AllowedDomains), tc.wantAllowed) || !reflect.DeepEqual(nilIfEmpty(got.Proxy.ForbiddenDomains), tc.wantForbidden) {
				t.Fatalf("allowed=%v forbidden=%v", got.Proxy.AllowedDomains, got.Proxy.ForbiddenDomains)
			}
		})
	}
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// The exact shape the factory's cube_egress policy produces for a claude
// harness: two paths on one host, the same injected credential.
func claudeRules(secret string) []sandbox.NetworkRule {
	rule := func(name, path string) sandbox.NetworkRule {
		return sandbox.NetworkRule{
			Name:  name,
			Match: sandbox.NetworkMatch{Scheme: "https", Host: "api.anthropic.com", SNI: "api.anthropic.com", Method: []string{"POST"}, Path: path},
			Action: sandbox.NetworkAction{Allow: true, Audit: "metadata", Inject: []sandbox.HeaderInjection{{
				Header: "x-api-key", Secret: secret, Format: "${SECRET}",
			}}},
		}
	}
	return []sandbox.NetworkRule{rule("factory-claude-model", "/v1/messages"), rule("factory-claude-model-1", "/v1/messages/count_tokens")}
}

func TestTranslateCredentialRules(t *testing.T) {
	got, err := translateNetwork(sandbox.Network{AllowInternet: boolPtr(false), AllowOut: []string{"registry.npmjs.org"}, Rules: claudeRules("sk-ant")})
	if err != nil {
		t.Fatal(err)
	}
	wantAllowed := []string{"registry.npmjs.org", "POST:api.anthropic.com/v1/messages", "POST:api.anthropic.com/v1/messages/count_tokens"}
	if !reflect.DeepEqual(got.Proxy.AllowedDomains, wantAllowed) {
		t.Fatalf("allowed = %v", got.Proxy.AllowedDomains)
	}
	wantRoutes := []proxyRoute{{
		Destinations: []string{"api.anthropic.com"},
		Headers:      map[string]string{"X-Api-Key": "{{SECRET:esf-secret-0}}"},
		Secrets:      map[string]string{"esf-secret-0": "sk-ant"},
	}}
	if !reflect.DeepEqual(got.Proxy.Routing, wantRoutes) {
		t.Fatalf("routes = %+v", got.Proxy.Routing)
	}
}

func TestTranslateBearerFormatAndWildcardPath(t *testing.T) {
	got, err := translateNetwork(sandbox.Network{AllowInternet: boolPtr(false), Rules: []sandbox.NetworkRule{{
		Name:   "m",
		Match:  sandbox.NetworkMatch{Host: "api.openai.com", Method: []string{"post", "GET"}, Path: "/v1/*"},
		Action: sandbox.NetworkAction{Allow: true, Inject: []sandbox.HeaderInjection{{Header: "authorization", Secret: "s", Format: "Bearer ${SECRET}"}}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Proxy.AllowedDomains[0] != "GET:POST:api.openai.com/v1/*" {
		t.Fatalf("pattern = %q", got.Proxy.AllowedDomains[0])
	}
	if got.Proxy.Routing[0].Headers["Authorization"] != "Bearer {{SECRET:esf-secret-0}}" {
		t.Fatalf("header = %v", got.Proxy.Routing[0].Headers)
	}
}

func TestTranslateRefusesUnenforceablePolicies(t *testing.T) {
	inject := sandbox.NetworkAction{Allow: true, Inject: []sandbox.HeaderInjection{{Header: "x-api-key", Secret: "s"}}}
	model := sandbox.NetworkMatch{Host: "api.anthropic.com", Method: []string{"POST"}, Path: "/v1/messages"}
	cases := map[string]sandbox.Network{
		"CIDR allow":               {AllowInternet: boolPtr(false), AllowOut: []string{"10.0.0.0/8"}},
		"IP deny":                  {DenyOut: []string{"169.254.169.254"}},
		"host with port":           {AllowInternet: boolPtr(false), AllowOut: []string{"github.com:22"}},
		"raw proxy syntax":         {AllowInternet: boolPtr(false), AllowOut: []string{"GET:github.com/x"}},
		"non-443 port":             {Rules: []sandbox.NetworkRule{{Name: "r", Match: sandbox.NetworkMatch{Host: "a.example", Port: 8443}, Action: sandbox.NetworkAction{Allow: true}}}},
		"plain http":               {Rules: []sandbox.NetworkRule{{Name: "r", Match: sandbox.NetworkMatch{Host: "a.example", Scheme: "http"}, Action: sandbox.NetworkAction{Allow: true}}}},
		"SNI differs":              {Rules: []sandbox.NetworkRule{{Name: "r", Match: sandbox.NetworkMatch{Host: "a.example", SNI: "b.example"}, Action: sandbox.NetworkAction{Allow: true}}}},
		"IP host":                  {Rules: []sandbox.NetworkRule{{Name: "r", Match: sandbox.NetworkMatch{Host: "1.2.3.4"}, Action: sandbox.NetworkAction{Allow: true}}}},
		"deny rule":                {Rules: []sandbox.NetworkRule{{Name: "r", Match: sandbox.NetworkMatch{Host: "a.example"}}}},
		"credential host open":     {AllowInternet: boolPtr(false), AllowOut: []string{"api.anthropic.com"}, Rules: []sandbox.NetworkRule{{Name: "r", Match: model, Action: inject}}},
		"credential host wildcard": {AllowInternet: boolPtr(false), AllowOut: []string{"*.anthropic.com"}, Rules: []sandbox.NetworkRule{{Name: "r", Match: model, Action: inject}}},
		"mixed injection on host": {AllowInternet: boolPtr(false), Rules: []sandbox.NetworkRule{
			{Name: "a", Match: model, Action: inject},
			{Name: "b", Match: sandbox.NetworkMatch{Host: "api.anthropic.com", Path: "/v1/files"}, Action: sandbox.NetworkAction{Allow: true}},
		}},
		"conflicting credentials": {AllowInternet: boolPtr(false), Rules: []sandbox.NetworkRule{
			{Name: "a", Match: model, Action: inject},
			{Name: "b", Match: model, Action: sandbox.NetworkAction{Allow: true, Inject: []sandbox.HeaderInjection{{Header: "x-api-key", Secret: "other"}}}},
		}},
		"credential under open egress": {Rules: []sandbox.NetworkRule{{Name: "r", Match: model, Action: inject}}},
		"format without secret":        {Rules: []sandbox.NetworkRule{{Name: "r", Match: model, Action: sandbox.NetworkAction{Allow: true, Inject: []sandbox.HeaderInjection{{Header: "h", Secret: "s", Format: "Bearer"}}}}}},
		"format with placeholder":      {Rules: []sandbox.NetworkRule{{Name: "r", Match: model, Action: sandbox.NetworkAction{Allow: true, Inject: []sandbox.HeaderInjection{{Header: "h", Secret: "s", Format: "${SECRET}{{SECRET:x}}"}}}}}},
		"empty secret":                 {Rules: []sandbox.NetworkRule{{Name: "r", Match: model, Action: sandbox.NetworkAction{Allow: true, Inject: []sandbox.HeaderInjection{{Header: "h"}}}}}},
		"bad method":                   {Rules: []sandbox.NetworkRule{{Name: "r", Match: sandbox.NetworkMatch{Host: "a.example", Method: []string{"GE:T"}}, Action: sandbox.NetworkAction{Allow: true}}}},
		"relative path":                {Rules: []sandbox.NetworkRule{{Name: "r", Match: sandbox.NetworkMatch{Host: "a.example", Path: "v1"}, Action: sandbox.NetworkAction{Allow: true}}}},
	}
	for name, n := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := translateNetwork(n); !errors.Is(err, ErrUnsupportedPolicy) {
				t.Fatalf("err = %v, want ErrUnsupportedPolicy", err)
			}
		})
	}
}

func TestDomainMatches(t *testing.T) {
	for _, tc := range []struct {
		pattern, host string
		want          bool
	}{
		{"*", "a.b", true},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "example.com", false},
		{"example.com", "example.com", true},
		{"example.com", "api.example.com", false},
	} {
		if got := domainMatches(tc.pattern, tc.host); got != tc.want {
			t.Errorf("domainMatches(%q, %q) = %v", tc.pattern, tc.host, got)
		}
	}
}
