package authkit

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/sessions"
)

func init() {
	// Register User with gob so gorilla/sessions can encode it in cookie stores.
	gob.Register(&User{})
}

const (
	sessionName    = "authkit_session"
	sessionUserKey = "user"
)

// newCookieStore builds the default secure cookie session store.
func newCookieStore(secret string, secure bool) *sessions.CookieStore {
	cs := sessions.NewCookieStore([]byte(secret))
	cs.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
	return cs
}

// saveUserToSession persists the User into the gorilla session and writes the
// Set-Cookie header. The User's permissions slice is serialised via JSON so it
// survives the gob round-trip on the CookieStore.
func saveUserToSession(store sessions.Store, w http.ResponseWriter, r *http.Request, u *User) error {
	sess, err := store.Get(r, sessionName)
	if err != nil {
		// Get() on a corrupt/missing cookie returns an error but also a fresh
		// session, so we can still use it.
		sess, _ = store.New(r, sessionName)
	}

	// Encode permissions separately as JSON so they survive gob round-trips.
	permJSON, err := json.Marshal(u.permissions)
	if err != nil {
		return fmt.Errorf("authkit: marshal permissions: %w", err)
	}

	sess.Values[sessionUserKey] = u
	sess.Values["permissions"] = string(permJSON)
	return store.Save(r, w, sess)
}

// userFromSession reads the User from the gorilla session cookie.
// Returns nil, nil when the session exists but contains no user (not logged in).
func userFromSession(store sessions.Store, r *http.Request) (*User, error) {
	sess, err := store.Get(r, sessionName)
	if err != nil {
		return nil, nil // corrupt or missing cookie — treat as unauthenticated
	}

	raw, ok := sess.Values[sessionUserKey]
	if !ok {
		return nil, nil
	}
	u, ok := raw.(*User)
	if !ok || u == nil {
		return nil, nil
	}

	// Restore permissions from the JSON side-car.
	if permRaw, ok := sess.Values["permissions"].(string); ok && permRaw != "" {
		var perms []string
		if err := json.Unmarshal([]byte(permRaw), &perms); err != nil {
			log.Printf("authkit: failed to deserialize session permissions: %v", err)
		} else {
			u.permissions = perms
		}
	}
	return u, nil
}

// clearSession invalidates the session cookie.
func clearSession(store sessions.Store, w http.ResponseWriter, r *http.Request) {
	sess, err := store.Get(r, sessionName)
	if err != nil {
		return
	}
	sess.Options.MaxAge = -1
	_ = store.Save(r, w, sess)
}
