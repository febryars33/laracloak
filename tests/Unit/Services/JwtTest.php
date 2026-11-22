<?php

declare(strict_types=1);

use Firebase\JWT\JWT as FirebaseJwt;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Snairbef\Laracloak\Exceptions\AuthenticationException;
use Snairbef\Laracloak\Services\Jwt;

beforeEach(function (): void {
    Cache::flush();

    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' => Http::response([
            'issuer' => 'http://localhost:8000',
            'authorization_endpoint' => 'http://localhost:8000/oauth/authorize',
            'token_endpoint' => 'http://localhost:8000/oauth/token',
            'jwks_uri' => 'http://localhost:8000/oauth/jwks',
            'userinfo_endpoint' => 'http://localhost:8000/oauth/userinfo',
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
            'jti' => 'logout-token-123',
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

it('rejects an ID token from another issuer', function (): void {
    app(Jwt::class)->validate(
        jwtToken([
            'iss' => 'https://other.example.com',
        ]),
    );
})->throws(
    AuthenticationException::class,
    'Invalid OIDC ID token issuer.',
);

it('rejects an ID token for another client', function (): void {
    app(Jwt::class)->validate(
        jwtToken([
            'aud' => 'another-client',
        ]),
    );
})->throws(
    AuthenticationException::class,
    'Invalid OIDC ID token audience.',
);

it('rejects ID tokens without required claims', function (string $claim): void {
    app(Jwt::class)->validate(
        jwtToken([
            $claim => null,
        ]),
    );
})->with([
    'issuer' => 'iss',
    'subject' => 'sub',
    'audience' => 'aud',
    'issued at' => 'iat',
    'expiration' => 'exp',
])->throws(AuthenticationException::class);

it('rejects an ID token with an invalid subject', function (string $subject): void {
    app(Jwt::class)->validate(
        jwtToken([
            'sub' => $subject,
        ]),
    );
})->with([
    'empty' => '',
    'too long' => str_repeat('a', 256),
    'non ASCII' => 'sübject',
])->throws(AuthenticationException::class);

it('rejects an ID token with multiple audiences and no authorized party', function (): void {
    app(Jwt::class)->validate(
        jwtToken([
            'aud' => ['test-client', 'another-client'],
        ]),
    );
})->throws(
    AuthenticationException::class,
    'Invalid OIDC ID token authorized party.',
);

it('validates an ID token with multiple audiences and a matching authorized party', function (): void {
    $claims = app(Jwt::class)->validate(
        jwtToken([
            'aud' => ['test-client', 'another-client'],
            'azp' => 'test-client',
        ]),
    );

    expect($claims->sub)
        ->toBe('subject-123');
});

it('rejects an ID token with an authorized party for another client', function (): void {
    app(Jwt::class)->validate(
        jwtToken([
            'azp' => 'another-client',
        ]),
    );
})->throws(
    AuthenticationException::class,
    'Invalid OIDC ID token authorized party.',
);

it('rejects an ID token with an unconfigured signing algorithm', function (): void {
    $token = FirebaseJwt::encode(
        [
            'iss' => 'http://localhost:8000',
            'aud' => 'test-client',
            'sub' => 'subject-123',
            'iat' => time(),
            'exp' => time() + 300,
        ],
        jwtPrivateKey(),
        'RS384',
        'test-key',
    );

    app(Jwt::class)->validate($token);
})->throws(
    AuthenticationException::class,
    'Invalid OIDC ID token algorithm.',
);

it('validates an ID token without a key identifier when one signing key is available', function (): void {
    $token = FirebaseJwt::encode(
        [
            'iss' => 'http://localhost:8000',
            'aud' => 'test-client',
            'sub' => 'subject-123',
            'iat' => time(),
            'exp' => time() + 300,
        ],
        jwtPrivateKey(),
        'RS256',
    );

    expect(app(Jwt::class)->validate($token)->sub)
        ->toBe('subject-123');
});

it('rejects an ID token issued in the future', function (): void {
    app(Jwt::class)->validate(
        jwtToken([
            'iat' => time() + 60,
        ]),
    );
})->throws(
    AuthenticationException::class,
);

it('rejects an invalid token', function (): void {
    app(Jwt::class)->validate(
        'invalid.token.value',
    );
})->throws(
    AuthenticationException::class,
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
        AuthenticationException::class,
    );
});

it('validates a back-channel logout token', function (): void {
    $jwt = app(Jwt::class);

    $token = jwtToken([
        'events' => [
            'http://schemas.openid.net/event/backchannel-logout' => (object) [],
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
    AuthenticationException::class,
    'Invalid OIDC logout event.',
);

it('rejects logout tokens for another client', function (): void {
    $token = jwtToken([
        'events' => [
            'http://schemas.openid.net/event/backchannel-logout' => (object) [],
        ],
        'aud' => 'another-client',
    ]);

    app(Jwt::class)->logout($token);
})->throws(
    AuthenticationException::class,
    'Invalid OIDC logout audience.',
);

it('rejects logout tokens from another issuer', function (): void {
    $token = jwtToken([
        'events' => [
            'http://schemas.openid.net/event/backchannel-logout' => (object) [],
        ],
        'iss' => 'http://evil.test',
    ]);

    app(Jwt::class)->logout($token);
})->throws(
    AuthenticationException::class,
    'Invalid OIDC logout issuer.',
);

it('rejects logout tokens without a subject', function (): void {
    $token = jwtToken([
        'sub' => null,
        'events' => [
            'http://schemas.openid.net/event/backchannel-logout' => (object) [],
        ],
    ]);

    app(Jwt::class)->logout($token);
})->throws(
    AuthenticationException::class,
    'OIDC logout subject is missing.',
);

it('rejects logout tokens without required claims', function (string $claim): void {
    app(Jwt::class)->logout(
        jwtToken([
            'events' => [
                'http://schemas.openid.net/event/backchannel-logout' => (object) [],
            ],
            $claim => null,
        ]),
    );
})->with([
    'issued at' => 'iat',
    'expiration' => 'exp',
    'token identifier' => 'jti',
])->throws(AuthenticationException::class);

it('rejects a logout token that contains a nonce', function (): void {
    app(Jwt::class)->logout(
        jwtToken([
            'events' => [
                'http://schemas.openid.net/event/backchannel-logout' => (object) [],
            ],
            'nonce' => 'unexpected-nonce',
        ]),
    );
})->throws(
    AuthenticationException::class,
    'OIDC logout token must not contain a nonce.',
);

it('rejects a logout token with a non-object event value', function (): void {
    app(Jwt::class)->logout(
        jwtToken([
            'events' => [
                'http://schemas.openid.net/event/backchannel-logout' => true,
            ],
        ]),
    );
})->throws(
    AuthenticationException::class,
    'Invalid OIDC logout event.',
);

it('validates a back-channel logout token with only sid', function (): void {
    $jwt = app(Jwt::class);

    $token = jwtToken([
        'sub' => null,
        'sid' => 'session-device-2',
        'events' => [
            'http://schemas.openid.net/event/backchannel-logout' => (object) [],
        ],
    ]);

    expect($jwt->logout($token))
        ->toMatchArray([
            'sid' => 'session-device-2',
        ]);
});
