<?php

declare(strict_types=1);

use Firebase\JWT\JWT as FirebaseJwt;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Snairbef\Laracloak\Exceptions\OidcException;
use Snairbef\Laracloak\Services\Jwt;

beforeEach(function (): void {
    Cache::flush();

    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' => Http::response([
            'issuer' => 'http://localhost:8000',
            'jwks_uri' => 'http://localhost:8000/oauth/jwks',
        ]),

        'http://localhost:8000/oauth/jwks' => Http::response(jwtJwks()),
    ]);
});

function jwtPrivateKey(): string
{
    return file_get_contents(
        __DIR__.'/../../Fixtures/keys/private.pem',
    );
}

function jwtToken(array $claims = []): string
{
    return FirebaseJwt::encode(
        array_merge([
            'iss' => 'http://localhost:8000',
            'aud' => 'test-client',
            'sub' => 'subject-123',
            'iat' => time(),
            'exp' => time() + 300,
        ], $claims),
        jwtPrivateKey(),
        'RS256',
        'test-key',
    );
}

function jwtJwks(): array
{
    $details = openssl_pkey_get_details(
        openssl_pkey_get_private(
            jwtPrivateKey(),
        ),
    );

    return [
        'keys' => [
            [
                'kty' => 'RSA',
                'kid' => 'test-key',
                'use' => 'sig',
                'alg' => 'RS256',
                'n' => rtrim(
                    strtr(
                        base64_encode($details['rsa']['n']),
                        '+/',
                        '-_',
                    ),
                    '=',
                ),
                'e' => rtrim(
                    strtr(
                        base64_encode($details['rsa']['e']),
                        '+/',
                        '-_',
                    ),
                    '=',
                ),
            ],
        ],
    ];
}

it('validates a signed ID token', function (): void {
    $jwt = app(Jwt::class);

    $claims = $jwt->validate(
        jwtToken(),
    );

    expect($claims->sub)
        ->toBe('subject-123');
});

it('rejects an invalid token', function (): void {
    app(Jwt::class)->validate(
        'invalid.token.value',
    );
})->throws(
    OidcException::class,
    'Invalid OIDC ID token.',
);

it('rejects a token signed by another key', function (): void {
    $other = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]);

    openssl_pkey_export(
        $other,
        $private,
    );

    $token = FirebaseJwt::encode(
        [
            'iss' => 'http://localhost:8000',
            'aud' => 'test-client',
            'sub' => 'subject-123',
            'iat' => time(),
            'exp' => time() + 300,
        ],
        $private,
        'RS256',
        'other-key',
    );

    expect(
        fn () => app(Jwt::class)->validate($token),
    )->toThrow(
        OidcException::class,
    );
});

it('validates a back-channel logout token', function (): void {
    $jwt = app(Jwt::class);

    $token = jwtToken([
        'events' => [
            'http://schemas.openid.net/event/backchannel-logout' => [],
        ],
    ]);

    expect($jwt->logout($token))
        ->toMatchArray([
            'sub' => 'subject-123',
        ]);
});

it('rejects logout tokens without the logout event', function (): void {
    app(Jwt::class)->logout(
        jwtToken(),
    );
})->throws(
    OidcException::class,
    'Invalid OIDC logout event.',
);

it('rejects logout tokens for another client', function (): void {
    $token = jwtToken([
        'events' => [
            'http://schemas.openid.net/event/backchannel-logout' => [],
        ],
        'aud' => 'another-client',
    ]);

    app(Jwt::class)->logout($token);
})->throws(
    OidcException::class,
    'Invalid OIDC logout audience.',
);

it('rejects logout tokens from another issuer', function (): void {
    $token = jwtToken([
        'events' => [
            'http://schemas.openid.net/event/backchannel-logout' => [],
        ],
        'iss' => 'http://evil.test',
    ]);

    app(Jwt::class)->logout($token);
})->throws(
    OidcException::class,
    'Invalid OIDC logout issuer.',
);

it('rejects logout tokens without a subject', function (): void {
    $token = jwtToken([
        'sub' => null,
        'events' => [
            'http://schemas.openid.net/event/backchannel-logout' => [],
        ],
    ]);

    app(Jwt::class)->logout($token);
})->throws(
    OidcException::class,
    'OIDC logout subject is missing.',
);
