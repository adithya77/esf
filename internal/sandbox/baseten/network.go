package baseten

import (
	"fmt"
	"net"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/mitkox/esf/internal/sandbox"
)

// proxyRuleset is the Blaxel firewall ruleset that forces all sandbox egress
// through the proxy. It can only be set at creation, so every sandbox gets it.
const proxyRuleset = "proxy"

// networkSpec is Blaxel's sandbox network block. An update replaces the whole
// block, so every write sends the firewall too.
type networkSpec struct {
	Firewall *firewallSpec `json:"firewall,omitempty"`
	Proxy    *proxySpec    `json:"proxy,omitempty"`
}

type firewallSpec struct {
	Rulesets []string `json:"rulesets"`
}

type proxySpec struct {
	AllowedDomains   []string     `json:"allowedDomains,omitempty"`
	ForbiddenDomains []string     `json:"forbiddenDomains,omitempty"`
	Routing          []proxyRoute `json:"routing,omitempty"`
}

// proxyRoute injects headers into requests to its destinations. Secrets are
// resolved by the proxy and are write-only in the API.
type proxyRoute struct {
	Destinations []string          `json:"destinations"`
	Headers      map[string]string `json:"headers,omitempty"`
	Secrets      map[string]string `json:"secrets,omitempty"`
}

func (n networkSpec) enforced() bool {
	return n.Firewall != nil && slices.Contains(n.Firewall.Rulesets, proxyRuleset) && n.Proxy != nil
}

// translateNetwork maps the factory's provider-neutral policy onto Blaxel's
// proxy. It refuses anything it cannot enforce exactly as strictly as asked:
// a policy that is silently weaker than requested produces evidence that lies.
//
// Semantics:
//   - Open internet (AllowInternet nil or true): every domain is allowed
//     except DenyOut. Blaxel treats an empty allowlist as "allow all", but an
//     empty proxy block is dropped by the API, so "*" is sent explicitly to
//     keep the proxy (and with it, later lockdown) in place.
//   - Closed internet: only AllowOut and allow-rules are reachable. With
//     nothing allowed, "*" is forbidden, because an empty allowlist would
//     mean "allow everything".
//   - Allow-rules become method/path-scoped allowlist entries; header
//     injections become proxy routes on the rule's host. The proxy injects on
//     every request to a routed host, so injection is refused under open
//     egress, and a routed host that is also allowed wholesale through
//     AllowOut is refused: the credential would reach every path, not only
//     the rule's.
//   - Blaxel matches paths as start-anchored prefixes (with * wildcards), so
//     an exact rule path also admits deeper paths on the same host and
//     methods. This is documented in docs/baseten.md.
func translateNetwork(n sandbox.Network) (networkSpec, error) {
	proxy := &proxySpec{}
	spec := networkSpec{Firewall: &firewallSpec{Rulesets: []string{proxyRuleset}}, Proxy: proxy}

	allowOut, err := domainPatterns("allow_out", n.AllowOut)
	if err != nil {
		return networkSpec{}, err
	}
	denyOut, err := domainPatterns("deny_out", n.DenyOut)
	if err != nil {
		return networkSpec{}, err
	}
	proxy.ForbiddenDomains = denyOut

	ruleAllows, routes, err := translateRules(n.Rules)
	if err != nil {
		return networkSpec{}, err
	}
	for _, route := range routes {
		for _, allowed := range allowOut {
			if domainMatches(allowed, route.Destinations[0]) {
				return networkSpec{}, fmt.Errorf("%w: %s is allowed wholesale by allow_out and also carries an injected credential; the proxy would attach the credential to every path on it", ErrUnsupportedPolicy, route.Destinations[0])
			}
		}
	}
	proxy.Routing = routes

	if n.AllowsInternet() {
		// The proxy injects on every request to a routed host. Only an
		// allowlist confines that to the rule's methods and paths, so an open
		// policy cannot carry a credential safely.
		if len(routes) > 0 {
			return networkSpec{}, fmt.Errorf("%w: credential injection requires allow_internet = false; with open egress the proxy would attach the credential to every request to %s", ErrUnsupportedPolicy, routes[0].Destinations[0])
		}
		// Rules and AllowOut add nothing to an open policy; DenyOut still
		// blocks. A "*" allowlist is only sent when
		// nothing is denied, so the two lists never compete for precedence.
		if len(denyOut) == 0 {
			proxy.AllowedDomains = []string{"*"}
		}
		return spec, nil
	}
	proxy.AllowedDomains = append(append([]string(nil), allowOut...), ruleAllows...)
	if len(proxy.AllowedDomains) == 0 {
		proxy.ForbiddenDomains = []string{"*"}
	}
	return spec, nil
}

// translateRules converts L7 rules into allowlist patterns and proxy routes.
func translateRules(rules []sandbox.NetworkRule) ([]string, []proxyRoute, error) {
	var allows []string
	routesByHost := map[string]*proxyRoute{}
	var hosts []string
	secretIndex := 0
	for _, rule := range rules {
		m := rule.Match
		host := strings.ToLower(strings.TrimSpace(m.Host))
		if host == "" || !isDNSName(host) {
			return nil, nil, fmt.Errorf("%w: rule %q needs a DNS host", ErrUnsupportedPolicy, rule.Name)
		}
		if m.SNI != "" && !strings.EqualFold(m.SNI, host) {
			return nil, nil, fmt.Errorf("%w: rule %q pins SNI %q to a different host than %q; the proxy matches on the request host only", ErrUnsupportedPolicy, rule.Name, m.SNI, host)
		}
		if m.Scheme != "" && !strings.EqualFold(m.Scheme, "https") {
			return nil, nil, fmt.Errorf("%w: rule %q: only https rules can be enforced", ErrUnsupportedPolicy, rule.Name)
		}
		if m.Port != 0 && m.Port != 443 {
			return nil, nil, fmt.Errorf("%w: rule %q: the proxy ignores ports, so port %d cannot be pinned", ErrUnsupportedPolicy, rule.Name, m.Port)
		}
		pattern, err := rulePattern(host, m.Method, m.Path)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: rule %q: %v", ErrUnsupportedPolicy, rule.Name, err)
		}
		if !rule.Action.Allow {
			if len(rule.Action.Inject) > 0 {
				return nil, nil, fmt.Errorf("%w: rule %q denies traffic but injects credentials", ErrUnsupportedPolicy, rule.Name)
			}
			// A deny rule is expressed through ForbiddenDomains by the caller's
			// DenyOut; the factory never emits one, so refuse rather than guess
			// at precedence against allow-rules.
			return nil, nil, fmt.Errorf("%w: rule %q: deny rules are not supported; use deny_out", ErrUnsupportedPolicy, rule.Name)
		}
		allows = append(allows, pattern)
		if len(rule.Action.Inject) == 0 {
			continue
		}
		route, ok := routesByHost[host]
		if !ok {
			route = &proxyRoute{Destinations: []string{host}, Headers: map[string]string{}, Secrets: map[string]string{}}
			routesByHost[host] = route
			hosts = append(hosts, host)
		}
		for _, inj := range rule.Action.Inject {
			header := http.CanonicalHeaderKey(strings.TrimSpace(inj.Header))
			if header == "" || strings.ContainsAny(header, ": \r\n") {
				return nil, nil, fmt.Errorf("%w: rule %q: invalid header name", ErrUnsupportedPolicy, rule.Name)
			}
			if inj.Secret == "" {
				return nil, nil, fmt.Errorf("%w: rule %q: header %s has no secret", ErrUnsupportedPolicy, rule.Name, header)
			}
			name := "esf-secret-" + strconv.Itoa(secretIndex)
			value, err := injectionValue(inj.Format, name)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: rule %q: %v", ErrUnsupportedPolicy, rule.Name, err)
			}
			// Routes apply per host, so two rules on one host must agree on
			// what they inject; otherwise one rule's credential would leak onto
			// the other rule's requests.
			if existing, ok := route.Headers[header]; ok {
				if route.Secrets[secretNameIn(existing)] != inj.Secret || !sameFormat(existing, value) {
					return nil, nil, fmt.Errorf("%w: rules on %s inject different values for %s; the proxy injects per host", ErrUnsupportedPolicy, host, header)
				}
				continue
			}
			route.Headers[header] = value
			route.Secrets[name] = inj.Secret
			secretIndex++
		}
	}
	// Two rules on a host with and without injection would let the
	// uninjected rule's paths receive the credential.
	for _, rule := range rules {
		host := strings.ToLower(strings.TrimSpace(rule.Match.Host))
		if _, routed := routesByHost[host]; routed && len(rule.Action.Inject) == 0 {
			return nil, nil, fmt.Errorf("%w: %s has rules with and without credential injection; the proxy injects on every request to the host", ErrUnsupportedPolicy, host)
		}
	}
	routes := make([]proxyRoute, 0, len(hosts))
	for _, host := range hosts {
		routes = append(routes, *routesByHost[host])
	}
	return allows, routes, nil
}

// rulePattern renders Blaxel's "[METHOD:...:]domain[/path]" allowlist syntax.
func rulePattern(host string, methods []string, path string) (string, error) {
	var b strings.Builder
	sorted := make([]string, 0, len(methods))
	for _, method := range methods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method == "" || strings.Trim(method, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
			return "", fmt.Errorf("invalid method %q", method)
		}
		sorted = append(sorted, method)
	}
	sort.Strings(sorted)
	for _, method := range sorted {
		b.WriteString(method)
		b.WriteByte(':')
	}
	b.WriteString(host)
	path = strings.TrimSpace(path)
	switch {
	case path == "" || path == "/*":
		// Every path.
	case !strings.HasPrefix(path, "/"):
		return "", fmt.Errorf("path %q must be absolute", path)
	case strings.ContainsAny(path, " ?#\r\n"):
		return "", fmt.Errorf("path %q contains characters the proxy cannot match", path)
	default:
		b.WriteString(path)
	}
	return b.String(), nil
}

// injectionValue converts the factory's ${SECRET} format into Blaxel's
// {{SECRET:name}} placeholder.
func injectionValue(format, name string) (string, error) {
	placeholder := "{{SECRET:" + name + "}}"
	if format == "" {
		return placeholder, nil
	}
	if strings.Count(format, "${SECRET}") != 1 {
		return "", fmt.Errorf("header format must contain ${SECRET} exactly once")
	}
	if strings.Contains(format, "{{") {
		return "", fmt.Errorf("header format must not contain proxy placeholders")
	}
	return strings.Replace(format, "${SECRET}", placeholder, 1), nil
}

func secretNameIn(value string) string {
	start := strings.Index(value, "{{SECRET:")
	if start < 0 {
		return ""
	}
	rest := value[start+len("{{SECRET:"):]
	end := strings.Index(rest, "}}")
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func sameFormat(a, b string) bool {
	return strings.Replace(a, "{{SECRET:"+secretNameIn(a)+"}}", "", 1) ==
		strings.Replace(b, "{{SECRET:"+secretNameIn(b)+"}}", "", 1)
}

// domainPatterns validates provider-neutral destinations. Blaxel's proxy
// filters by domain, so IP addresses and CIDRs cannot be enforced and are
// refused rather than silently ignored.
func domainPatterns(field string, entries []string) ([]string, error) {
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		e := strings.ToLower(strings.TrimSpace(entry))
		if e == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(e); err == nil || net.ParseIP(e) != nil {
			return nil, fmt.Errorf("%w: %s entry %q is an IP or CIDR; the Baseten proxy filters by domain only", ErrUnsupportedPolicy, field, entry)
		}
		name := strings.TrimPrefix(e, "*.")
		if e != "*" && !isDNSName(name) {
			return nil, fmt.Errorf("%w: %s entry %q must be a domain or *.domain", ErrUnsupportedPolicy, field, entry)
		}
		out = append(out, e)
	}
	return out, nil
}

// domainMatches applies the proxy's domain rule: "*" matches everything,
// "*.x" matches subdomains of x but not x itself, anything else is exact.
func domainMatches(pattern, host string) bool {
	switch {
	case pattern == "*":
		return true
	case strings.HasPrefix(pattern, "*."):
		return strings.HasSuffix(host, pattern[1:])
	default:
		return pattern == host
	}
}

func isDNSName(s string) bool {
	if s == "" || len(s) > 253 || net.ParseIP(s) != nil || !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
