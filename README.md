# Laracloak

[![Latest Version on Packagist](https://img.shields.io/packagist/v/snairbef/laracloak.svg?style=flat-square)](https://packagist.org/packages/snairbef/laracloak)
[![Total Downloads](https://img.shields.io/packagist/dt/snairbef/laracloak.svg?style=flat-square)](https://packagist.org/packages/snairbef/laracloak)
[![Tests](https://github.com/febryars33/laracloak/actions/workflows/run-tests.yml/badge.svg)](https://github.com/febryars33/laracloak/actions/workflows/run-tests.yml)
[![PHPStan](https://github.com/febryars33/laracloak/actions/workflows/phpstan.yml/badge.svg)](https://github.com/febryars33/laracloak/actions/workflows/phpstan.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE.md)

**Laravel-native OpenID Connect authentication with SSO, SLO, token refresh, and Back-Channel Logout.**

Laracloak is a Laravel package that provides an OpenID Connect (OIDC) client implementation for Laravel applications. It integrates OIDC authentication directly into Laravel's native authentication system through a dedicated `laracloak` guard and supports Authorization Code Flow with PKCE, ID Token validation, UserInfo synchronization, automatic access-token refresh, Single Sign-On (SSO), Single Logout (SLO), and OpenID Connect Back-Channel Logout.

Laracloak is provider-agnostic. It does not require Keycloak and can work with any OIDC provider that implements the required OpenID Connect endpoints and flows.

## Features

- OpenID Connect Authorization Code Flow
- PKCE with `S256`
- OIDC Discovery
- ID Token validation using JWKS
- JWT signature validation with `RS256`
- Issuer validation
- Audience validation
- Nonce validation
- Authorization state validation
- UserInfo endpoint integration
- ID Token subject and UserInfo subject validation
- Automatic access-token refresh
- Refresh-token rotation support
- Concurrent refresh protection
- Laravel native authentication guard
- Local Eloquent user provisioning
- Local user profile synchronization
- Subject-based session revocation
- Single Sign-On (SSO)
- Single Logout (SLO)
- RP-Initiated Logout
- OpenID Connect Back-Channel Logout
- Discovery and JWKS caching
- Laravel session integration
- Laravel intended URL support
- Strict PHPStan analysis
- Pest test suite

## Requirements

- PHP 8.3+
- Laravel 13.x
- An OpenID Connect Provider
- PHP OpenSSL extension
- PHP JSON extension
- PHP cURL extension

Your OIDC provider must support:

- Authorization Code Flow
- PKCE
- OpenID Connect Discovery
- ID Tokens
- JWKS
- UserInfo
- Refresh Tokens
- RP-Initiated Logout
- Back-Channel Logout if Back-Channel Logout is required

## Installation

Install the package using Composer:

```bash
composer require snairbef/laracloak
```

Publish the configuration:

```bash
php artisan vendor:publish --tag="laracloak-config"
```

The configuration file will be published to:

```text
config/laracloak.php
```

## Configuration

The package uses Laravel configuration and environment variables.

A typical configuration looks like this:

```php
<?php

return [
    'issuer' => env(
        'LARACLOAK_ISSUER',
        'http://localhost:8000',
    ),

    'client' => [
        'id' => env('LARACLOAK_CLIENT_ID'),
        'secret' => env('LARACLOAK_CLIENT_SECRET'),
    ],

    'redirect' => [
        'login' => env(
            'LARACLOAK_REDIRECT_URI',
            'http://localhost:8001/auth/callback',
        ),
    ],

    'authentication' => [
        'method' => env(
            'LARACLOAK_AUTHENTICATION_METHOD',
            'client_secret_post',
        ),
    ],

    'scopes' => [
        'openid',
        'profile',
        'email',
    ],

    'identity' => [
        'ttl' => env(
            'LARACLOAK_IDENTITY_TTL',
            30,
        ),
    ],

    'user' => [
        'model' => env(
            'LARACLOAK_USER_MODEL',
            'App\\Models\\User',
        ),

        'provision' => env(
            'LARACLOAK_USER_PROVISION',
            true,
        ),
    ],

    'session' => [
        'flow' => 'laracloak.flow',
        'token' => 'laracloak.token',
        'user' => 'laracloak.user',
        'identity_at' => 'laracloak.identity_at',
    ],

    'logout_endpoint' => env(
        'LARACLOAK_LOGOUT_ENDPOINT',
        'http://localhost:8000/oauth/logout',
    ),

    'post_logout_redirect_uri' => env(
        'LARACLOAK_POST_LOGOUT_REDIRECT_URI',
        'http://localhost:8001/',
    ),
];
```

## Environment

Configure your OIDC client in `.env`:

```dotenv
LARACLOAK_ISSUER=http://localhost:8000

LARACLOAK_CLIENT_ID=your-client-id
LARACLOAK_CLIENT_SECRET=your-client-secret

LARACLOAK_REDIRECT_URI=http://localhost:8001/auth/callback

LARACLOAK_AUTHENTICATION_METHOD=client_secret_post

LARACLOAK_IDENTITY_TTL=30

LARACLOAK_USER_MODEL=App\\Models\\User
LARACLOAK_USER_PROVISION=true

LARACLOAK_LOGOUT_ENDPOINT=http://localhost:8000/oauth/logout

LARACLOAK_POST_LOGOUT_REDIRECT_URI=http://localhost:8001/
```

The `LARACLOAK_ISSUER` must point to the OIDC provider's issuer.

Laracloak automatically discovers the provider configuration from:

```text
{issuer}/.well-known/openid-configuration
```

For example:

```text
http://localhost:8000/.well-known/openid-configuration
```

## OIDC Discovery

Laracloak uses OpenID Connect Discovery to obtain the provider endpoints.

A valid discovery document should provide the endpoints required by the package, including:

```json
{
    "issuer": "http://localhost:8000",
    "authorization_endpoint": "http://localhost:8000/oauth/authorize",
    "token_endpoint": "http://localhost:8000/oauth/token",
    "userinfo_endpoint": "http://localhost:8000/oauth/userinfo",
    "jwks_uri": "http://localhost:8000/oauth/jwks",
    "end_session_endpoint": "http://localhost:8000/oauth/logout"
}
```

The discovery document and JWKS are cached to avoid unnecessary requests to the provider.

## Laravel Authentication Guard

Laracloak integrates with Laravel's native authentication system through the `laracloak` guard.

The package registers the guard and provider automatically.

You can use Laravel's standard authentication APIs:

```php
use Illuminate\Support\Facades\Auth;

$user = Auth::user();

$id = Auth::id();

if (Auth::check()) {
    // Authenticated
}
```

You can also explicitly use the Laracloak guard:

```php
Auth::guard('laracloak')->check();

Auth::guard('laracloak')->user();

Auth::guard('laracloak')->id();
```

The package also provides the `oidc()` guard indicator:

```php
Auth::guard('laracloak')->oidc();
```

which returns:

```php
true
```

## Protecting Routes

Laracloak works with Laravel's native `auth` middleware.

For example:

```php
use Illuminate\Support\Facades\Route;

Route::middleware('auth')->group(function () {
    Route::get('/dashboard', function () {
        return view('dashboard');
    });
});
```

When an unauthenticated user accesses a protected route, Laravel redirects the user to the Laracloak login route.

The package registers:

```text
GET  /auth/login
GET  /auth/callback
POST /auth/logout
POST /auth/backchannel-logout
```

## Login Flow

The login flow follows the OpenID Connect Authorization Code Flow with PKCE.

```text
Laravel Application
        │
        │ GET /auth/login
        ▼
    Laracloak
        │
        │ Authorization Request
        │ + state
        │ + nonce
        │ + PKCE S256
        ▼
  OIDC Provider
        │
        │ User Authentication
        ▼
  OIDC Provider
        │
        │ Authorization Code
        ▼
    Laracloak
        │
        │ Token Request
        │ + authorization_code
        │ + code_verifier
        ▼
  OIDC Provider
        │
        │ Access Token
        │ ID Token
        │ Refresh Token
        ▼
    Laracloak
        │
        │ Validate ID Token
        │ Validate UserInfo
        │ Synchronize User
        ▼
 Laravel Application
        │
        ▼
 Authenticated Session
```

### Login

Use the package login route:

```text
/auth/login
```

For example:

```html
<a href="/auth/login">
    Login
</a>
```

Or:

```php
return redirect()->route('laracloak.login');
```

## User Provisioning

After successful authentication, Laracloak resolves the OIDC subject (`sub`) against the configured Laravel user model.

For example, an OIDC provider may return:

```json
{
    "sub": "user-123",
    "name": "John Doe",
    "email": "johndoe@example.com"
}
```

Laracloak will look for:

```text
users.sub = user-123
```

If the user exists, the profile is synchronized.

If the user does not exist and provisioning is enabled, Laracloak creates the local user.

By default:

```dotenv
LARACLOAK_USER_PROVISION=true
```

The default user model is:

```text
App\Models\User
```

You can configure another Eloquent model:

```dotenv
LARACLOAK_USER_MODEL=App\\Models\\User
```

The configured model must implement Laravel's `Authenticatable` contract and extend Eloquent's `Model`.

### Database

Your application's users table should contain a unique `sub` column.

Example:

```php
$table->string('sub')->unique();
```

A typical user record becomes:

```text
id       = 25
sub      = user-123
name     = John Doe
email    = johndoe@example.com
```

Laravel authentication still uses the local Eloquent primary key:

```php
Auth::id();        // 25
Auth::user()->id;  // 25
```

The OIDC identity is represented by:

```php
Auth::user()->sub; // user-123
```

## UserInfo

After authentication, Laracloak retrieves the authenticated user's profile from the provider's UserInfo endpoint.

The access token is sent as a Bearer token:

```http
Authorization: Bearer <access-token>
```

The `sub` claim returned by UserInfo must match the authenticated OIDC identity.

This prevents an access token from being associated with a different OIDC subject.

## Token Refresh

Laracloak automatically refreshes an expired or near-expiry access token using the refresh token.

The refresh process includes:

- Access-token expiry detection
- Refresh-token exchange
- Refresh-token rotation support
- Session token replacement
- Concurrent refresh protection

The package uses a cache lock to prevent multiple simultaneous requests from refreshing the same session token at the same time.

Applications normally do not need to manually refresh the access token.

## Logout

Logout is performed through Laravel's POST route:

```text
POST /auth/logout
```

Example:

```html
<form method="POST" action="/auth/logout">
    @csrf

    <button type="submit">
        Logout
    </button>
</form>
```

The client clears its local authentication session and redirects the user to the provider's OIDC logout endpoint.

If the provider supports `end_session_endpoint`, Laracloak uses the discovered endpoint automatically.

The logout request can include:

- `id_token_hint`
- `post_logout_redirect_uri`
- `client_id`

## Single Logout

Laracloak supports OIDC Single Logout.

The intended flow is:

```text
Application A
     │
     │ Logout
     ▼
OIDC Provider
     │
     │ Provider Session Ended
     ▼
Other OIDC Clients
     │
     │ Back-Channel Logout
     ▼
Laracloak
     │
     │ Revoke subject
     ▼
Local Session
     │
     ▼
Logged Out
```

This allows one provider logout to invalidate authenticated sessions in connected Laravel applications.

## Back-Channel Logout

Laracloak provides an endpoint for OpenID Connect Back-Channel Logout:

```text
POST /auth/backchannel-logout
```

The OIDC provider sends a signed logout token:

```http
POST /auth/backchannel-logout
Content-Type: application/x-www-form-urlencoded

logout_token=<signed-jwt>
```

Laracloak validates:

- JWT signature
- JWKS key
- Issuer
- Audience
- Subject
- Back-Channel Logout event

The required logout event is:

```text
http://schemas.openid.net/event/backchannel-logout
```

After successful validation, the OIDC subject is revoked locally.

Subsequent authentication checks will reject the revoked subject.

## Subject-Based Revocation

Laracloak maintains a revocation state based on the OIDC subject.

For example:

```text
OIDC subject
    │
    ▼
user-123
    │
    ▼
Revoked
    │
    ▼
Local authentication rejected
```

This makes provider-initiated logout effective even when an existing Laravel session is still present.

## Security

Laracloak implements several protections required for a secure OIDC client:

### State Validation

The authorization state is generated cryptographically and validated during the callback.

This protects against login CSRF and authorization response injection.

### Nonce Validation

A cryptographically random nonce is generated for every authentication flow and verified against the ID Token.

### PKCE

Laracloak uses PKCE with the `S256` challenge method.

```text
code_verifier
      │
      │ SHA-256
      ▼
code_challenge
```

The original verifier is never sent in the authorization request.

### ID Token Validation

ID Tokens are validated against the provider's JWKS.

Validation includes:

- JWT signature
- Issuer
- Audience
- Expiration
- Nonce
- Subject

### UserInfo Subject Validation

The `sub` claim from UserInfo must match the authenticated OIDC subject.

### Back-Channel Logout Validation

Logout tokens are cryptographically verified before the corresponding subject is revoked.

## Production Recommendations

For production environments:

- Always use HTTPS.
- Use secure and HTTP-only Laravel session cookies.
- Store client secrets in environment variables or a secret manager.
- Never commit client secrets to Git.
- Configure a unique `sub` index on the users table.
- Use a shared cache when running multiple application instances.
- Configure correct trusted proxy settings when running behind a reverse proxy.
- Rate-limit authentication endpoints where appropriate.
- Keep Laravel, PHP, and dependencies up to date.
- Configure the OIDC provider with exact redirect URIs.
- Configure the Back-Channel Logout URI explicitly in the provider.

## Testing

Laracloak uses Pest for automated testing and PHPStan for static analysis.

Run the complete test suite:

```bash
composer test
```

Run Laravel Pint:

```bash
./vendor/bin/pint
```

Run PHPStan:

```bash
./vendor/bin/phpstan analyse
```

The project test suite covers:

- OIDC authentication
- Authorization flow
- PKCE
- State
- JWT validation
- JWKS
- UserInfo
- Token refresh
- Revocation
- Back-Channel Logout
- Authentication guard
- User provisioning
- HTTP client
- Service provider
- Routes
- Architecture rules

## Architecture

Laracloak is organized around small, focused services.

```text
src/
├── Auth/
│   ├── Guard.php
│   ├── Provider.php
│   └── UserResolver.php
│
├── Contracts/
│
├── Exceptions/
│
├── Http/
│   ├── Client.php
│   └── Controllers/
│       └── OidcController.php
│
├── Models/
│
├── Services/
│   ├── Discovery.php
│   ├── Identity.php
│   ├── Jwt.php
│   ├── Oidc.php
│   ├── Revocation.php
│   ├── Token.php
│   └── Userinfo.php
│
└── Support/
    ├── Pkce.php
    └── State.php
```

The package follows separation of concerns and keeps OIDC responsibilities isolated from Laravel authentication concerns.

## Provider Compatibility

Laracloak is not tied to Keycloak.

It can be used with any provider implementing the required OpenID Connect functionality.

For example:

- Custom Laravel OIDC providers
- Auth0
- Keycloak
- Authentik
- Microsoft Entra ID
- Other standards-compliant OIDC providers

The provider must expose a compatible discovery document and support the flows required by your application.

## Example Provider

A compatible discovery document might look like:

```json
{
    "issuer": "https://auth.example.com",
    "authorization_endpoint": "https://auth.example.com/oauth/authorize",
    "token_endpoint": "https://auth.example.com/oauth/token",
    "userinfo_endpoint": "https://auth.example.com/oauth/userinfo",
    "jwks_uri": "https://auth.example.com/oauth/jwks",
    "end_session_endpoint": "https://auth.example.com/oauth/logout"
}
```

The exact endpoint URLs depend on your OIDC provider.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the latest changes.

## Security Vulnerabilities

If you discover a security vulnerability, please do not create a public GitHub issue.

Instead, report the vulnerability privately through the repository's security reporting mechanism.

## Contributing

Contributions, bug reports, and improvements are welcome.

Before submitting a pull request, make sure the following commands pass:

```bash
./vendor/bin/pint
composer test
./vendor/bin/phpstan analyse
```

Please keep changes focused, tested, and compatible with the supported Laravel and PHP versions.

## Credits

- [Febriansyah Riki Setiadi](https://github.com/febryars33)

## License

Laracloak is open-sourced software licensed under the [MIT license](LICENSE.md).
