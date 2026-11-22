# Changelog

All notable changes to `laracloak` will be documented in this file.

## v1.0.0-rc.3 - 2026-11-22

- Fix guest redirects when Laravel resolves the HTTP kernel before package providers boot.

**Full Changelog**: https://github.com/febryars33/laracloak/compare/v1.0.0-rc.2...v1.0.0-rc.3

## v1.0.0-rc.2 - 2026-11-22

- Limit supported Laravel versions to 12 and 13; Laravel 11 dependencies are blocked by Composer security advisories.
- Restrict the CI compatibility matrix to the supported Laravel versions.

**Full Changelog**: https://github.com/febryars33/laracloak/compare/v1.0.0-rc.1...v1.0.0-rc.2

## v1.0.0-rc.1 - 2026-11-22

- Hardened OIDC Discovery, ID Token, and Back-Channel Logout validation.
- Added expiring, one-time authorization flows with multi-tab support and session ID regeneration.
- Added `client_secret_basic` authentication and preserved sessions for transient token endpoint failures.
- Aligned Laravel authentication IDs with local Eloquent primary keys and clarified unsupported password/remember-me APIs.
- Added Laravel 12 and 13 to the CI compatibility matrix.

**Full Changelog**: https://github.com/febryars33/laracloak/compare/v0.1.1...v1.0.0-rc.1

## v0.1.1 - 2026-11-19

**Full Changelog**: https://github.com/febryars33/laracloak/compare/v0.1.0...v0.1.1

## Initial Public Release - 2026-11-19

**Full Changelog**: https://github.com/febryars33/laracloak/compare/v0.1.0-alpha.5...v0.1.0
