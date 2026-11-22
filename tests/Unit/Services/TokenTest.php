<?php

use Illuminate\Http\Client\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Http;
use Snairbef\Laracloak\Exceptions\AuthenticationException;
use Snairbef\Laracloak\Exceptions\ConfigurationException;
use Snairbef\Laracloak\Exceptions\HttpException;
use Snairbef\Laracloak\Http\Client;
use Snairbef\Laracloak\Services\Discovery;
use Snairbef\Laracloak\Services\Token;

function tokenSession(): Store
{
    $session = new Store(
        'test',
        new ArraySessionHandler(3600),
    );

    $session->start();

    return $session;
}

it('exchanges an authorization code', function () {
    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' => Http::response([
            'issuer' => 'http://localhost:8000',
            'authorization_endpoint' => 'http://localhost:8000/oauth/authorize',
            'token_endpoint' => 'http://localhost:8000/oauth/token',
            'jwks_uri' => 'http://localhost:8000/oauth/jwks',
            'userinfo_endpoint' => 'http://localhost:8000/oauth/userinfo',
        ]),

        'http://localhost:8000/oauth/token' => Http::response([
            'access_token' => 'access-token',
            'refresh_token' => 'refresh-token',
            'expires_in' => 3600,
            'token_type' => 'Bearer',
        ]),
    ]);

    $token = new Token(
        new Client,
        app(Discovery::class),
        tokenSession(),
    );

    $tokens = $token->exchange(
        'authorization-code',
        'verifier',
    );

    expect($tokens)
        ->toHaveKey('access_token', 'access-token')
        ->toHaveKey('refresh_token', 'refresh-token')
        ->toHaveKey('created_at');
});

it('authenticates the token request with client secret basic', function () {
    config()->set(
        'laracloak.authentication.method',
        'client_secret_basic',
    );

    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' => Http::response([
            'issuer' => 'http://localhost:8000',
            'authorization_endpoint' => 'http://localhost:8000/oauth/authorize',
            'token_endpoint' => 'http://localhost:8000/oauth/token',
            'jwks_uri' => 'http://localhost:8000/oauth/jwks',
            'userinfo_endpoint' => 'http://localhost:8000/oauth/userinfo',
        ]),

        'http://localhost:8000/oauth/token' => Http::response([
            'access_token' => 'access-token',
            'token_type' => 'Bearer',
        ]),
    ]);

    $token = new Token(
        new Client,
        app(Discovery::class),
        tokenSession(),
    );

    $token->exchange('authorization-code', 'verifier');

    Http::assertSent(fn (Request $request): bool => $request->hasHeader(
        'Authorization',
        'Basic '.base64_encode('test-client:test-secret'),
    ) && ! array_key_exists('client_secret', $request->data()));
});

it('rejects unsupported token endpoint authentication methods', function () {
    config()->set(
        'laracloak.authentication.method',
        'client_secret_jwt',
    );

    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' => Http::response([
            'issuer' => 'http://localhost:8000',
            'authorization_endpoint' => 'http://localhost:8000/oauth/authorize',
            'token_endpoint' => 'http://localhost:8000/oauth/token',
            'jwks_uri' => 'http://localhost:8000/oauth/jwks',
            'userinfo_endpoint' => 'http://localhost:8000/oauth/userinfo',
        ]),
    ]);

    $token = new Token(
        new Client,
        app(Discovery::class),
        tokenSession(),
    );

    $token->exchange('authorization-code', 'verifier');
})->throws(
    ConfigurationException::class,
    'Unsupported OIDC token endpoint authentication method.',
);

it('refreshes a token', function () {
    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' => Http::response([
            'issuer' => 'http://localhost:8000',
            'authorization_endpoint' => 'http://localhost:8000/oauth/authorize',
            'token_endpoint' => 'http://localhost:8000/oauth/token',
            'jwks_uri' => 'http://localhost:8000/oauth/jwks',
            'userinfo_endpoint' => 'http://localhost:8000/oauth/userinfo',
        ]),

        'http://localhost:8000/oauth/token' => Http::response([
            'access_token' => 'new-access-token',
            'expires_in' => 3600,
            'token_type' => 'Bearer',
        ]),
    ]);

    $token = new Token(
        new Client,
        app(Discovery::class),
        tokenSession(),
    );

    $tokens = $token->refresh('refresh-token');

    expect($tokens['access_token'])
        ->toBe('new-access-token')
        ->and($tokens['refresh_token'])
        ->toBe('refresh-token');
});

it('returns an unexpired access token', function () {
    $session = tokenSession();

    $session->put(
        'laracloak.token',
        [
            'access_token' => 'access-token',
            'refresh_token' => 'refresh-token',
            'created_at' => now()->timestamp,
            'expires_in' => 3600,
        ],
    );

    $token = new Token(
        new Client,
        app(Discovery::class),
        $session,
    );

    expect($token->access())
        ->toBe('access-token');
});

it('returns null without tokens', function () {
    $token = new Token(
        new Client,
        app(Discovery::class),
        tokenSession(),
    );

    expect($token->access())
        ->toBeNull();
});

it('clears session when access token is missing', function () {
    $session = tokenSession();

    $session->put(
        'laracloak.token',
        [
            'refresh_token' => 'refresh-token',
            'created_at' => now()->timestamp,
            'expires_in' => 3600,
        ],
    );

    $token = new Token(
        new Client,
        app(Discovery::class),
        $session,
    );

    $result = $token->access();

    expect($result)->toBeNull();
    expect($session->has('laracloak.token'))->toBeFalse();
});

it('preserves session when refresh response is malformed', function () {
    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' => Http::response([
            'issuer' => 'http://localhost:8000',
            'authorization_endpoint' => 'http://localhost:8000/oauth/authorize',
            'token_endpoint' => 'http://localhost:8000/oauth/token',
            'jwks_uri' => 'http://localhost:8000/oauth/jwks',
            'userinfo_endpoint' => 'http://localhost:8000/oauth/userinfo',
        ]),

        'http://localhost:8000/oauth/token' => Http::response([
            'expires_in' => 3600,
        ]),
    ]);

    $session = tokenSession();

    $tokens = [
        'access_token' => 'old',
        'refresh_token' => 'refresh-token',
        'created_at' => now()->subHours(2)->timestamp,
        'expires_in' => 60,
    ];
    $session->put('laracloak.token', $tokens);

    $token = new Token(
        new Client,
        app(Discovery::class),
        $session,
    );

    expect(fn () => $token->access())
        ->toThrow(AuthenticationException::class, 'Invalid OIDC token response.');
    expect($session->get('laracloak.token'))->toBe($tokens);
});

it('preserves the session for non-invalid refresh errors', function (string $error, int $status) {
    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' => Http::response([
            'issuer' => 'http://localhost:8000',
            'authorization_endpoint' => 'http://localhost:8000/oauth/authorize',
            'token_endpoint' => 'http://localhost:8000/oauth/token',
            'jwks_uri' => 'http://localhost:8000/oauth/jwks',
            'userinfo_endpoint' => 'http://localhost:8000/oauth/userinfo',
        ]),

        'http://localhost:8000/oauth/token' => Http::response([
            'error' => $error,
        ], $status),
    ]);

    $session = tokenSession();
    $tokens = [
        'access_token' => 'old-access-token',
        'refresh_token' => 'refresh-token',
        'created_at' => now()->subHours(2)->timestamp,
        'expires_in' => 60,
    ];
    $session->put('laracloak.token', $tokens);
    $token = new Token(
        new Client,
        app(Discovery::class),
        $session,
    );

    expect(fn () => $token->access())
        ->toThrow(HttpException::class);

    expect($session->get('laracloak.token'))
        ->toBe($tokens);
})->with([
    ['temporarily_unavailable', 429],
    ['temporarily_unavailable', 503],
    ['invalid_client', 401],
]);

it('clears the session when the provider rejects the refresh grant', function () {
    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' => Http::response([
            'issuer' => 'http://localhost:8000',
            'authorization_endpoint' => 'http://localhost:8000/oauth/authorize',
            'token_endpoint' => 'http://localhost:8000/oauth/token',
            'jwks_uri' => 'http://localhost:8000/oauth/jwks',
            'userinfo_endpoint' => 'http://localhost:8000/oauth/userinfo',
        ]),

        'http://localhost:8000/oauth/token' => Http::response([
            'error' => 'invalid_grant',
        ], 400),
    ]);

    $session = tokenSession();
    $session->put('laracloak.token', [
        'access_token' => 'old-access-token',
        'refresh_token' => 'revoked-refresh-token',
        'created_at' => now()->subHours(2)->timestamp,
        'expires_in' => 60,
    ]);

    $token = new Token(
        new Client,
        app(Discovery::class),
        $session,
    );

    expect($token->access())
        ->toBeNull()
        ->and($session->has('laracloak.token'))
        ->toBeFalse();
});
