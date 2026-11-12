package factory

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/mitkox/esf/internal/sandbox"
)

const githubHost = "github.com"

// GitHub owner and repository names. Repository names may start with a dot
// (the org-wide .github repository) but may not be "." or "..".
var (
	githubOwner = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)
	githubRepo  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
)

// repositoryCloneNetwork returns the temporary egress policy that lets a
// sandbox fetch one GitHub repository with a proxy-injected token.
//
// It applies only when a GitHub token is configured and the repository is an
// https://github.com/<owner>/<repo> URL (which admission has already matched
// against repositories.allowed). The policy denies all other egress and
// allows exactly the two smart-HTTP requests a fetch makes, GET .../info/refs
// and POST .../git-upload-pack, for that repository only. The token is
// injected by the provider's proxy as HTTP Basic credentials, so it never
// enters the sandbox; it is resolved here, in the worker, and is never part of
// workflow input or evidence.
//
// The second return value lists the secret forms to register with the
// redactor before the policy is sent anywhere.
func (c Config) repositoryCloneNetwork(rawURL string) (sandbox.Network, []string, bool, error) {
	tokenFile := strings.TrimSpace(c.Repositories.GitHubTokenFile)
	if tokenFile == "" {
		return sandbox.Network{}, nil, false, nil
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || !strings.EqualFold(u.Scheme, "https") || !strings.EqualFold(u.Host, githubHost) {
		// Only https://github.com URLs carry the token; anything else is
		// fetched without credentials, exactly as before.
		return sandbox.Network{}, nil, false, nil
	}
	owner, repo, err := githubRepository(u.Path)
	if err != nil {
		return sandbox.Network{}, nil, false, err
	}
	token, basic, err := readGitHubCredential(tokenFile)
	if err != nil {
		return sandbox.Network{}, nil, false, err
	}

	network := sandbox.Network{AllowInternet: boolPointer(false)}
	inject := []sandbox.HeaderInjection{{Header: "Authorization", Secret: basic, Format: "Basic ${SECRET}"}}
	// Exactly the fetch endpoints: the ref advertisement and upload-pack.
	// git-receive-pack (push) and every other path stay blocked, so even a
	// token with write scope can only be used to read this repository.
	for _, base := range []string{"/" + owner + "/" + repo, "/" + owner + "/" + repo + ".git"} {
		for _, endpoint := range []struct{ method, path string }{
			{"GET", base + "/info/refs"},
			{"POST", base + "/git-upload-pack"},
		} {
			network.Rules = append(network.Rules, sandbox.NetworkRule{
				Name: "factory-repository-clone",
				Match: sandbox.NetworkMatch{
					Scheme: "https", Host: githubHost, SNI: githubHost,
					Method: []string{endpoint.method}, Path: endpoint.path,
				},
				Action: sandbox.NetworkAction{Allow: true, Audit: "metadata", Inject: inject},
			})
		}
	}
	return network, []string{token, basic}, true, nil
}

// githubRepository splits /owner/repo(.git) and refuses anything else, so a
// rule can never be widened to an owner or to another repository.
func githubRepository(p string) (string, string, error) {
	trimmed := strings.Trim(p, "/")
	if strings.HasSuffix(trimmed, ".git") && !strings.HasSuffix(trimmed, "/.git") {
		trimmed = strings.TrimSuffix(trimmed, ".git")
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 || !githubOwner.MatchString(parts[0]) || !githubRepo.MatchString(parts[1]) || parts[1] == "." || parts[1] == ".." {
		return "", "", fmt.Errorf("%q is not a github.com/<owner>/<repository> URL path", p)
	}
	return parts[0], parts[1], nil
}

// repositoryCredentialSecrets registers the GitHub token (and its Basic form)
// with the redactor at startup. CheckRepositoryCredentials has already
// verified the file is readable when the worker starts.
func (c Config) repositoryCredentialSecrets() []string {
	tokenFile := strings.TrimSpace(c.Repositories.GitHubTokenFile)
	if tokenFile == "" {
		return nil
	}
	token, basic, err := readGitHubCredential(tokenFile)
	if err != nil {
		return nil
	}
	return []string{token, basic}
}

// CheckRepositoryCredentials verifies at worker start that a configured token
// file is readable and owner-only, so a bad file fails the deployment, not
// the first run that needs it.
func (c Config) CheckRepositoryCredentials() error {
	tokenFile := strings.TrimSpace(c.Repositories.GitHubTokenFile)
	if tokenFile == "" {
		return nil
	}
	_, _, err := readGitHubCredential(tokenFile)
	return err
}

// readGitHubCredential returns the token and the HTTP Basic value git's
// smart-HTTP transport sends for it. Both forms come from here so the value
// injected and the value redacted can never drift apart.
func readGitHubCredential(tokenFile string) (token, basic string, err error) {
	token, err = readCredentialFile(tokenFile)
	if err != nil {
		return "", "", fmt.Errorf("repositories.github_token_file: %w", err)
	}
	return token, base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token)), nil
}
