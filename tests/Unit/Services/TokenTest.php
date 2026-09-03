<?php

use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Http;
use Snairbef\Laracloak\Exceptions\OidcException;
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
            'token_endpoint' => 'http://localhost:8000/oauth/token',
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

it('refreshes a token', function () {
    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' => Http::response([
            'token_endpoint' => 'http://localhost:8000/oauth/token',
        ]),

        'http://localhost:8000/oauth/token' => Http::response([
            'access_token' => 'new-access-token',
            'expires_in' => 3600,
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

it('rejects a missing access token', function () {
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

    $token->access();
})->throws(
    OidcException::class,
    'OIDC access token is missing.',
);

it('rejects refresh responses without an access token', function () {
    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' => Http::response([
            'token_endpoint' => 'http://localhost:8000/oauth/token',
        ]),

        'http://localhost:8000/oauth/token' => Http::response([
            'expires_in' => 3600,
        ]),
    ]);

    $session = tokenSession();

    $session->put(
        'laracloak.token',
        [
            'access_token' => 'old',
            'refresh_token' => 'refresh-token',
            'created_at' => now()->subHours(2)->timestamp,
            'expires_in' => 60,
        ],
    );

    $token = new Token(
        new Client,
        app(Discovery::class),
        $session,
    );

    $token->access();
})->throws(OidcException::class);
