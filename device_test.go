package authkit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockDeviceValidator is a test double for DeviceTokenValidator.
type mockDeviceValidator struct {
	rec *DeviceRecord
	err error
}

func (m *mockDeviceValidator) ValidateDeviceToken(_ context.Context, _ string) (*DeviceRecord, error) {
	return m.rec, m.err
}

func deviceAuth(rec *DeviceRecord) *Auth {
	return &Auth{deviceValidator: &mockDeviceValidator{rec: rec}}
}

func deviceRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/print/status", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func TestDevice_Can_OnlyPrintCaps(t *testing.T) {
	d := &Device{AgentID: "a1", TenantID: "t1", BranchID: "b1"}
	for _, ok := range []string{CapPrintJobReceive, CapPrintStatusReport} {
		if !d.Can(ok) {
			t.Errorf("device should hold %q", ok)
		}
	}
	for _, no := range []string{"*", "invoice:issue", "agent:enroll", "print:other"} {
		if d.Can(no) {
			t.Errorf("device must NOT hold %q", no)
		}
	}
	var nilDev *Device
	if nilDev.Can(CapPrintJobReceive) {
		t.Error("nil device must hold nothing")
	}
}

func TestRequireDevice_ValidToken_BindsTenantAndDevice(t *testing.T) {
	rec := &DeviceRecord{AgentID: "agent-1", Name: "Front Desk", TenantID: "tnt-1", BranchID: "brn-1"}
	a := deviceAuth(rec)

	var gotDevice *Device
	var gotTenant string
	var ok bool
	h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotDevice = DeviceFromCtx(r.Context())
		gotTenant, ok = TenantIDFromCtx(r.Context())
	})

	w := httptest.NewRecorder()
	a.RequireDevice(CapPrintStatusReport)(h).ServeHTTP(w, deviceRequest("dev-token"))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if gotDevice == nil || gotDevice.AgentID != "agent-1" || gotDevice.BranchID != "brn-1" {
		t.Fatalf("device not bound: %+v", gotDevice)
	}
	if !ok || gotTenant != "tnt-1" {
		t.Fatalf("tenant not bound on ctx: %q (ok=%v)", gotTenant, ok)
	}
}

func TestRequireDevice_NoToken_401(t *testing.T) {
	a := deviceAuth(&DeviceRecord{AgentID: "x", TenantID: "t"})
	called := false
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })

	w := httptest.NewRecorder()
	a.RequireDevice(CapPrintJobReceive)(h).ServeHTTP(w, deviceRequest(""))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if called {
		t.Error("next must not run without a token")
	}
}

func TestRequireDevice_UnknownToken_401(t *testing.T) {
	a := &Auth{deviceValidator: &mockDeviceValidator{rec: nil}} // validator finds nothing
	called := false
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })

	w := httptest.NewRecorder()
	a.RequireDevice(CapPrintJobReceive)(h).ServeHTTP(w, deviceRequest("ghost"))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if called {
		t.Error("next must not run for an unknown token")
	}
}

func TestRequireDevice_NoValidator_401(t *testing.T) {
	a := &Auth{} // device auth disabled
	w := httptest.NewRecorder()
	a.RequireDevice(CapPrintJobReceive)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("next must not run")
	})).ServeHTTP(w, deviceRequest("anything"))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestRequireDevice_NonDeviceCapability_Panics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("RequireDevice with a non-device capability must panic at wire time")
		}
	}()
	deviceAuth(&DeviceRecord{}).RequireDevice("invoice:issue")
}

func TestAuthenticateDevice_BuildsPrincipal(t *testing.T) {
	rec := &DeviceRecord{AgentID: "a", Name: "n", TenantID: "t", BranchID: "b"}
	d, err := deviceAuth(rec).AuthenticateDevice(context.Background(), "tok")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if d.AgentID != "a" || d.TenantID != "t" || d.BranchID != "b" {
		t.Fatalf("principal mismatch: %+v", d)
	}
}

func TestAuthenticateDevice_Errors(t *testing.T) {
	if _, err := (&Auth{}).AuthenticateDevice(context.Background(), "tok"); err != ErrDeviceTokenInvalid {
		t.Errorf("no validator: err = %v, want ErrDeviceTokenInvalid", err)
	}
	if _, err := deviceAuth(nil).AuthenticateDevice(context.Background(), ""); err != ErrDeviceTokenInvalid {
		t.Errorf("empty token: err = %v, want ErrDeviceTokenInvalid", err)
	}
	if _, err := deviceAuth(nil).AuthenticateDevice(context.Background(), "tok"); err != ErrDeviceTokenInvalid {
		t.Errorf("unknown token: err = %v, want ErrDeviceTokenInvalid", err)
	}
}
