module github.com/tlmanz/authkit/redisstore/v2

go 1.25.0

require (
	github.com/alicebob/miniredis/v2 v2.35.0
	github.com/redis/go-redis/v9 v9.21.0
	github.com/tlmanz/authkit/v2 v2.0.0
)

require (
	cloud.google.com/go/compute/metadata v0.3.0 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-chi/chi/v5 v5.2.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/gorilla/context v1.1.1 // indirect
	github.com/gorilla/mux v1.6.2 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/gorilla/sessions v1.4.0 // indirect
	github.com/markbates/goth v1.82.0 // indirect
	github.com/pquerna/otp v1.5.0 // indirect
	github.com/yuin/gopher-lua v1.1.1 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/crypto v0.49.0 // indirect
	golang.org/x/oauth2 v0.27.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Local development against the sibling core module in this repository.
// Ignored by consumers (replace directives only apply to the main module),
// so the published redisstore module resolves authkit/v2 from the proxy.
replace github.com/tlmanz/authkit/v2 => ../
