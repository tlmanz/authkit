package authkit

import (
	"strings"
	"testing"
)

func TestBuildProvider_GitHub(t *testing.T) {
	p, err := buildProvider(ProviderConfig{
		Name:         "github",
		ClientID:     "test-id",
		ClientSecret: "test-secret",
	}, "https://example.com")
	if err != nil {
		t.Fatalf("buildProvider: %v", err)
	}
	if p.Name() != "github" {
		t.Errorf("name: got %q, want github", p.Name())
	}
}

func TestBuildProvider_Google(t *testing.T) {
	p, err := buildProvider(ProviderConfig{
		Name:         "google",
		ClientID:     "test-id",
		ClientSecret: "test-secret",
	}, "https://example.com")
	if err != nil {
		t.Fatalf("buildProvider: %v", err)
	}
	if p.Name() != "google" {
		t.Errorf("name: got %q, want google", p.Name())
	}
}

func TestBuildProvider_GitLab(t *testing.T) {
	p, err := buildProvider(ProviderConfig{
		Name:         "gitlab",
		ClientID:     "test-id",
		ClientSecret: "test-secret",
	}, "https://example.com")
	if err != nil {
		t.Fatalf("buildProvider: %v", err)
	}
	if p.Name() != "gitlab" {
		t.Errorf("name: got %q, want gitlab", p.Name())
	}
}

func TestBuildProvider_UnsupportedProvider(t *testing.T) {
	_, err := buildProvider(ProviderConfig{
		Name:         "twitter",
		ClientID:     "test-id",
		ClientSecret: "test-secret",
	}, "https://example.com")
	if err == nil {
		t.Fatal("expected error for unsupported provider")
	}
	if !strings.Contains(err.Error(), "unsupported provider") {
		t.Errorf("error should mention unsupported: %v", err)
	}
}

func TestBuildProvider_CustomScopes(t *testing.T) {
	p, err := buildProvider(ProviderConfig{
		Name:         "github",
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		Scopes:       []string{"repo", "user"},
	}, "https://example.com")
	if err != nil {
		t.Fatalf("buildProvider: %v", err)
	}
	if p.Name() != "github" {
		t.Errorf("name: got %q, want github", p.Name())
	}
}

func TestBuildProviders_Multiple(t *testing.T) {
	providers, err := buildProviders([]ProviderConfig{
		{Name: "github", ClientID: "id1", ClientSecret: "s1"},
		{Name: "google", ClientID: "id2", ClientSecret: "s2"},
	}, "https://example.com")
	if err != nil {
		t.Fatalf("buildProviders: %v", err)
	}
	if len(providers) != 2 {
		t.Errorf("count: got %d, want 2", len(providers))
	}
}

func TestBuildProviders_ErrorPropagates(t *testing.T) {
	_, err := buildProviders([]ProviderConfig{
		{Name: "github", ClientID: "id1", ClientSecret: "s1"},
		{Name: "invalid", ClientID: "id2", ClientSecret: "s2"},
	}, "https://example.com")
	if err == nil {
		t.Fatal("expected error to propagate from invalid provider")
	}
}
