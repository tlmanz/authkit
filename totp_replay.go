package authkit

import (
	"context"
	"crypto/subtle"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTP anti-replay. A TOTP code is valid for its whole time-step window (here
// ~90s with skew 1), so an intercepted code can otherwise be submitted more than
// once inside that window (phishing relay, a racing second login). To close that,
// a store MAY implement TOTPReplayGuard: authkit resolves the exact time-step the
// submitted code belongs to and claims it, so each code is usable at most once.
// Stores that don't implement it keep the prior behavior (no replay protection),
// so this is a non-breaking, opt-in capability.

const (
	totpPeriodSeconds = 30
	totpSkewSteps     = 1
)

// TOTPReplayGuard is the optional capability. ClaimTOTPTimestep atomically
// records timestep as consumed for (tenant, email) and returns ok=false when it
// was already consumed (or a later step already was), i.e. a replay. The store
// keeps only the last-consumed step per user; it need not remember all of them.
type TOTPReplayGuard interface {
	ClaimTOTPTimestep(ctx context.Context, tenantID, email string, timestep int64) (ok bool, err error)
}

// PlatformTOTPReplayGuard is the platform-admin equivalent (keyed by email only;
// platform admins have no tenant).
type PlatformTOTPReplayGuard interface {
	ClaimPlatformTOTPTimestep(ctx context.Context, email string, timestep int64) (ok bool, err error)
}

// matchTOTPTimestep returns the Unix time-step (t/period) the code validates for
// within the skew window, or ok=false if the code is not valid. It mirrors the
// parameters of totp.Validate (period 30, skew 1, 6 digits, SHA1) so it accepts
// exactly the same codes, but also tells us WHICH step matched.
func matchTOTPTimestep(code, secret string, now time.Time) (int64, bool) {
	opts := totp.ValidateOpts{Period: totpPeriodSeconds, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
	for d := -totpSkewSteps; d <= totpSkewSteps; d++ {
		t := now.Add(time.Duration(d) * totpPeriodSeconds * time.Second)
		want, err := totp.GenerateCodeCustom(secret, t, opts)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return t.Unix() / totpPeriodSeconds, true
		}
	}
	return 0, false
}
