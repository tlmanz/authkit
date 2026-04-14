package authkit

import (
	"fmt"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/bitbucket"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/gitlab"
	"github.com/markbates/goth/providers/google"
)

// ProviderConfig holds the OAuth credentials for a single provider.
type ProviderConfig struct {
	// Name is the provider identifier for the built-in wrappers: "bitbucket", "github", "google", or "gitlab".
	// For any other provider, use Config.GothProviders instead.
	Name string

	// ClientID and ClientSecret are the OAuth application credentials.
	ClientID     string
	ClientSecret string

	// Scopes overrides the default scopes for the provider.
	// Leave nil to use the sensible defaults (email + profile).
	Scopes []string
}

// defaultScopes returns the minimum scopes needed to retrieve an email address
// and display name for each supported provider.
var defaultScopes = map[string][]string{
	"bitbucket": {"account", "email"},
	"github":    {"user:email"},
	"google":    {"email", "profile"},
	"gitlab":    {"read_user"},
}

// buildProviders converts the config slice into registered goth.Providers.
// The OAuth callback URL is derived as {callbackBaseURL}/auth/{name}/callback.
func buildProviders(cfgs []ProviderConfig, callbackBaseURL string) ([]goth.Provider, error) {
	providers := make([]goth.Provider, 0, len(cfgs))
	for _, c := range cfgs {
		p, err := buildProvider(c, callbackBaseURL)
		if err != nil {
			return nil, err
		}
		providers = append(providers, p)
	}
	return providers, nil
}

func buildProvider(c ProviderConfig, callbackBaseURL string) (goth.Provider, error) {
	scopes := c.Scopes
	if len(scopes) == 0 {
		scopes = defaultScopes[c.Name]
	}
	callbackURL := callbackBaseURL + "/auth/" + c.Name + "/callback"

	switch c.Name {
	case "bitbucket":
		return bitbucket.New(c.ClientID, c.ClientSecret, callbackURL, scopes...), nil
	case "github":
		return github.New(c.ClientID, c.ClientSecret, callbackURL, scopes...), nil
	case "google":
		return google.New(c.ClientID, c.ClientSecret, callbackURL, scopes...), nil
	case "gitlab":
		return gitlab.New(c.ClientID, c.ClientSecret, callbackURL, scopes...), nil
	default:
		return nil, fmt.Errorf("authkit: unsupported provider name %q — use \"github\", \"google\", or \"gitlab\", or pass a pre-built goth.Provider via Config.GothProviders", c.Name)
	}
}
