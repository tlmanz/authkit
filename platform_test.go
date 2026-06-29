package authkit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

const platformTOTPSecret = "JBSWY3DPEHPK3PXP"

type memPlatformStore struct{ rec *PlatformAdminRecord }

func (m *memPlatformStore) GetPlatformAdmin(_ context.Context, email string) (*PlatformAdminRecord, error) {
	if m.rec == nil || !strings.EqualFold(email, m.rec.Email) {
		return nil, ErrUserNotFound
	}
	return m.rec, nil
}

func (m *memPlatformStore) UpdatePassword(_ context.Context, email, hashed string) error {
	if m.rec == nil || !strings.EqualFold(email, m.rec.Email) {
		return ErrUserNotFound
	}
	m.rec.HashedPassword = hashed
	return nil
}

type staticPlatformPolicy struct{}

func (staticPlatformPolicy) PermissionsForPlatformRole(role string) []string {
	switch role {
	case "super_admin":
		return []string{PermAll}
	case "support":
		return []string{"platform:tenant.read", "platform:impersonate"}
	default:
		return nil
	}
}

type capturingAudit struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (c *capturingAudit) Emit(_ context.Context, ev AuditEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
}
func (c *capturingAudit) count(typ string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, e := range c.events {
		if e.Type == typ {
			n++
		}
	}
	return n
}

func platformAuth(t *testing.T, role string, audit AuditSink) *Auth {
	t.Helper()
	pw, _ := HashPassword("super-secret-pw")
	a, err := New(Config{
		Mode:          AuthModePassword,
		SessionSecret: "0123456789abcdef0123456789abcdef",
		UserStore:     stubUserStore{},
		SessionStore:  newMemStore(),
		AuditSink:     audit,
		PlatformAdminStore: &memPlatformStore{rec: &PlatformAdminRecord{
			Email: "root@klutch.lk", Name: "Root", HashedPassword: pw, Role: role, TOTPSecret: platformTOTPSecret,
		}},
		PlatformPolicy:      staticPlatformPolicy{},
		EnableImpersonation: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

// platformPasswordStep posts step 1 (email + password) and returns the recorder.
func platformPasswordStep(t *testing.T, a *Auth, password string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	form := url.Values{"email": {"root@klutch.lk"}, "password": {password}}
	req := httptest.NewRequest("POST", "/platform/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.0.0.9:5555"
	a.PlatformLogin(rec, req)
	return rec
}

// platformLogin runs the full two-step flow (password → TOTP) and returns the
// platform session cookie.
func platformLogin(t *testing.T, a *Auth) *http.Cookie {
	t.Helper()
	rec := platformPasswordStep(t, a, "super-secret-pw")
	if rec.Code != http.StatusOK {
		t.Fatalf("platform login step1 = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	pending := findCookie(rec, a.platformPendingCookieName())
	if pending == nil {
		t.Fatal("no platform pending cookie after password step")
	}

	code, _ := totp.GenerateCode(platformTOTPSecret, time.Now())
	rec2 := httptest.NewRecorder()
	form := url.Values{"code": {code}}
	req := httptest.NewRequest("POST", "/platform/2fa/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.0.0.9:5555"
	req.AddCookie(pending)
	a.PlatformVerify2FA(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("platform verify step2 = %d, want 200; body=%s", rec2.Code, rec2.Body.String())
	}
	c := findCookie(rec2, a.platformCookieName())
	if c == nil {
		t.Fatal("no platform session cookie issued")
	}
	return c
}

func TestPlatformLogin_TwoStepPasswordThenTOTP(t *testing.T) {
	audit := &capturingAudit{}
	a := platformAuth(t, "super_admin", audit)

	// Wrong password → step 1 401, no pending cookie, no session.
	rec := platformPasswordStep(t, a, "wrong-pw")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad password = %d, want 401", rec.Code)
	}
	if findCookie(rec, a.platformPendingCookieName()) != nil {
		t.Fatal("pending cookie issued for a wrong password")
	}

	// Correct password → step 1 200 (2fa_required) + pending cookie.
	rec = platformPasswordStep(t, a, "super-secret-pw")
	if rec.Code != http.StatusOK {
		t.Fatalf("good password step1 = %d, want 200", rec.Code)
	}
	pending := findCookie(rec, a.platformPendingCookieName())
	if pending == nil {
		t.Fatal("no pending cookie after correct password")
	}
	if findCookie(rec, a.platformCookieName()) != nil {
		t.Fatal("session minted before TOTP step")
	}

	// Wrong TOTP at step 2 → 401, no session.
	rec2 := httptest.NewRecorder()
	form := url.Values{"code": {"000000"}}
	req := httptest.NewRequest("POST", "/platform/2fa/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.0.0.9:5555"
	req.AddCookie(pending)
	a.PlatformVerify2FA(rec2, req)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("bad TOTP = %d, want 401", rec2.Code)
	}

	// Verify with no pending cookie → 401.
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest("POST", "/platform/2fa/verify", strings.NewReader(form.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	a.PlatformVerify2FA(rec3, req3)
	if rec3.Code != http.StatusUnauthorized {
		t.Fatalf("verify without pending = %d, want 401", rec3.Code)
	}

	// Full correct flow → 200 + audit login.
	platformLogin(t, a)
	if audit.count(AuditLogin) < 1 {
		t.Fatal("expected an audit login event")
	}
}

func TestRequirePlatformAdmin_Gating(t *testing.T) {
	// super_admin has "*", so passes any perm.
	a := platformAuth(t, "super_admin", &capturingAudit{})
	cookie := platformLogin(t, a)

	call := func(perm string, c *http.Cookie) int {
		h := a.RequirePlatformAdmin(perm)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if PlatformAdminFromCtx(r.Context()) == nil {
				t.Fatal("no platform admin in ctx")
			}
			w.WriteHeader(http.StatusOK)
		}))
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/platform/tenants", nil)
		if c != nil {
			req.AddCookie(c)
		}
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := call("platform:tenant.onboard", cookie); code != http.StatusOK {
		t.Fatalf("super_admin onboard = %d, want 200", code)
	}
	if code := call("platform:tenant.onboard", nil); code != http.StatusUnauthorized {
		t.Fatalf("no cookie = %d, want 401", code)
	}

	// support lacks tenant.onboard → 403.
	sa := platformAuth(t, "support", &capturingAudit{})
	scookie := platformLogin(t, sa)
	h := sa.RequirePlatformAdmin("platform:tenant.onboard")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/platform/tenants", nil)
	req.AddCookie(scookie)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("support onboard = %d, want 403", rec.Code)
	}
}

func TestImpersonation_PermGatedAndAudited(t *testing.T) {
	audit := &capturingAudit{}
	a := platformAuth(t, "support", audit) // support has platform:impersonate

	admin := &PlatformAdmin{Email: "root@klutch.lk", Role: "support", permissions: []string{"platform:impersonate"}}
	ctx, err := a.ImpersonationContext(context.Background(), admin, "tenant-123")
	if err != nil {
		t.Fatalf("impersonate: %v", err)
	}
	if id, ok := TenantIDFromCtx(ctx); !ok || id != "tenant-123" {
		t.Fatalf("impersonation ctx tenant = (%q, %v), want tenant-123", id, ok)
	}
	if audit.count(AuditImpersonate) != 1 {
		t.Fatal("impersonation not audited")
	}

	// An admin without the capability is rejected.
	noperm := &PlatformAdmin{Email: "x", Role: "none"}
	if _, err := a.ImpersonationContext(context.Background(), noperm, "tenant-123"); err == nil {
		t.Fatal("impersonation allowed without capability")
	}
}
