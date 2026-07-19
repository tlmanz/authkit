package authkit

import (
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

// authkit's endpoints accept both classic form encoding and JSON bodies, so a
// server-rendered form, an SPA using fetch with JSON, and a mobile client all
// speak to the same handlers. Handlers call parseBody(r) once, after which
// r.FormValue transparently reads either encoding.

const maxAuthBodyBytes = 1 << 20 // auth payloads are tiny; bound the decoder

// isJSONRequest reports whether the request declares a JSON body.
func isJSONRequest(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return false
	}
	mt, _, err := mime.ParseMediaType(ct)
	return err == nil && (mt == "application/json" || strings.HasSuffix(mt, "+json"))
}

// parseBody prepares the request for FormValue access. For JSON requests it
// decodes the body once into r.Form (top-level string values; other scalars
// keep their literal form, so {"remember": true} reads as "true"). For any
// other encoding it is a no-op — FormValue parses form bodies itself.
func parseBody(r *http.Request) {
	if !isJSONRequest(r) || r.Form != nil {
		return
	}
	form := url.Values{}
	if r.Body != nil {
		var raw map[string]json.RawMessage
		dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxAuthBodyBytes))
		if err := dec.Decode(&raw); err == nil {
			for k, msg := range raw {
				var s string
				if json.Unmarshal(msg, &s) == nil {
					form.Set(k, s)
					continue
				}
				form.Set(k, strings.Trim(string(msg), `"`))
			}
		}
	}
	// Merge query parameters the way ParseForm would, so JSON requests do not
	// lose URL values.
	if q := r.URL.Query(); len(q) > 0 {
		for k, vs := range q {
			if form.Get(k) == "" && len(vs) > 0 {
				form.Set(k, vs[0])
			}
		}
	}
	r.Form = form
}
