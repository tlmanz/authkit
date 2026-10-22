# Changelog

Release notes for `github.com/tlmanz/authkit/v2`. The Redis stores
(`github.com/tlmanz/authkit/redisstore/v2`) are released separately; see
[redisstore/CHANGELOG.md](redisstore/CHANGELOG.md).

Each `## [vX.Y.Z]` section below becomes that version's GitHub release notes
when its tag is pushed (see [RELEASING.md](RELEASING.md)). Dates are MM/DD/YY.

## [v2.0.1] - 10/22/26

### Security

- **2FA that a user turns on themselves is now enforced at sign-in.** A login
  only asked for a code when the user's role was in `RequireForRoles`, so a user
  who enrolled voluntarily (for example from an account page) was never
  challenged, on web or native sign-in. A confirmed TOTP secret now triggers the
  challenge in `Login`, `ChangeFirstPassword` and `IssuePasswordToken`. If the
  2FA state cannot be read, the login fails with a 500 instead of going ahead
  without a code.
- **Turning 2FA off, or replacing the recovery codes, now takes the second
  factor.** `DisableTwoFactor` and `RegenerateRecoveryCodes` require a current
  `code` or a `recovery_code`; a session alone (an unlocked shared computer, a
  stolen cookie) was enough to remove the protection above, or to mint recovery
  codes that pass it. Wrong codes are throttled per account and IP like a login,
  so a stolen session cannot guess its way through.
- **A remembered device no longer skips setting up a new authenticator.** When a
  role requires 2FA and the user's authenticator had been removed (an admin
  reset, say), a browser or device that remembered them signed them straight in
  and they were never asked to enroll again. A remembered device now skips only
  the code for an authenticator that is confirmed, as the platform-admin login
  already did.

### Fixed

- **"Remember this device" now remembers every account on a browser, not only
  the last one.** The trusted-device cookie held a single token, so when a
  second account (another member of staff, or a platform admin) ticked
  "remember" on the same browser, the first account was asked for a 2FA code
  again on its next login. The cookie now holds one entry per account, labelled
  with a keyed hash of the account so a sign-in asks the store about its own
  entry only, however many accounts the browser remembers.
- **"Log out everywhere" forgets only the signed-out user's trust on that
  browser.** Other accounts the browser remembers keep theirs; previously the
  whole cookie was cleared.
- A sign-in reads the TOTP secret once; it was read twice when a code was due.

### Compatibility

- **Clients must send a code to turn 2FA off or to regenerate recovery codes.**
  `POST /auth/2fa/disable` and `POST /auth/2fa/recovery/regenerate` now answer
  400 `invalid_code` without a valid `code` or `recovery_code` (429 once
  throttled).
- **Users who enabled 2FA voluntarily will now be asked for a code when they
  sign in.** That is the fix, but it is a visible change for them. A pending
  enrollment that was never confirmed does not trigger it. Every password
  sign-in now reads `TOTPStore.Secret` once, including for roles that do not
  require 2FA; a store whose `Secret` errors for a pending enrollment it cannot
  read will fail those sign-ins, so report such an enrollment as none instead.
- No exported API or `TrustedDeviceStore` changes. A cookie written by v2.0.0
  (one raw token) is still read, so browsers remembered before the upgrade stay
  remembered. The new cookie's labels are keyed on `SessionSecret`, so rotating
  that secret makes browsers forget who they remembered (one 2FA prompt each).
- There is no cap on how many accounts a browser remembers. The cookie is kept
  under the ~4 KB browsers accept (around fifty accounts with the Redis store's
  tokens); past that, the oldest are dropped first rather than the browser
  silently discarding the whole cookie.
- The native token flow is unchanged: the app still presents its own token per
  login. Native clients that keep a single token per device have the same
  one-account limit on their side.
- OAuth sign-in (`Callback`) still does not run a 2FA step, as before.

## [v2.0.0] - 07/19/26

Major release with breaking changes. See [MIGRATION.md](MIGRATION.md) for the
upgrade from v1.
