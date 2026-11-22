<?php

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Snairbef\Laracloak\Exceptions\ConfigurationException;
use Snairbef\Laracloak\Services\Discovery;

beforeEach(function () {
    Cache::flush();
});

function discoveryDocument(array $override = []): array
{
    return array_merge([
        'issuer' => 'http://localhost:8000',
        'authorization_endpoint' => 'http://localhost:8000/oauth/authorize',
        'token_endpoint' => 'http://localhost:8000/oauth/token',
        'jwks_uri' => 'http://localhost:8000/oauth/jwks',
        'userinfo_endpoint' => 'http://localhost:8000/oauth/userinfo',
    ], $override);
}

it('loads OIDC discovery metadata', function () {
    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' => Http::response(
            discoveryDocument(),
        ),
    ]);

    $discovery = app(Discovery::class);

    expect($discovery->get())
        ->toMatchArray([
            'issuer' => 'http://localhost:8000',
        ]);
});

it('returns a specific discovery field', function () {
    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' => Http::response(
            discoveryDocument(),
        ),
    ]);

    $discovery = app(Discovery::class);

    expect($discovery->get('userinfo_endpoint'))
        ->toBe('http://localhost:8000/oauth/userinfo');
});

it('caches discovery metadata', function () {
    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' => Http::response(
            discoveryDocument(),
        ),
    ]);

    $discovery = app(Discovery::class);

    $discovery->get();
    $discovery->get();

    Http::assertSentCount(1);
});

it('throws when a discovery field is missing', function () {
    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' => Http::response(
            discoveryDocument([
                'userinfo_endpoint' => '',
            ]),
        ),
    ]);

    app(Discovery::class)->get('userinfo_endpoint');
})->throws(
    ConfigurationException::class,
    'OIDC discovery field [userinfo_endpoint] is missing.',
);

it('rejects an invalid issuer', function () {
    config()->set(
        'laracloak.issuer',
        'invalid',
    );

    app(Discovery::class)->get();
})->throws(
    ConfigurationException::class,
    'Invalid OIDC issuer: invalid',
);

it('rejects a public HTTP issuer', function () {
    config()->set(
        'laracloak.issuer',
        'http://provider.test',
    );

    Http::fake([
        'http://provider.test/*' => Http::response(
            discoveryDocument([
                'issuer' => 'http://provider.test',
                'authorization_endpoint' => 'https://provider.test/oauth/authorize',
                'token_endpoint' => 'https://provider.test/oauth/token',
                'jwks_uri' => 'https://provider.test/oauth/jwks',
                'userinfo_endpoint' => 'https://provider.test/oauth/userinfo',
            ]),
        ),
    ]);

    app(Discovery::class)->get();
})->throws(
    ConfigurationException::class,
    'OIDC issuer must use HTTPS except for loopback hosts.',
);

it('rejects a discovery issuer mismatch', function () {
    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' => Http::response(
            discoveryDocument([
                'issuer' => 'https://other.test',
            ]),
        ),
    ]);

    app(Discovery::class)->get();
})->throws(
    ConfigurationException::class,
    'OIDC discovery issuer does not match the configured issuer.',
);

it('rejects a discovery issuer that differs by a trailing slash', function () {
    config()->set(
        'laracloak.issuer',
        'https://provider.test',
    );

    Http::fake([
        'https://provider.test/*' => Http::response(
            discoveryDocument([
                'issuer' => 'https://provider.test/',
                'authorization_endpoint' => 'https://provider.test/oauth/authorize',
                'token_endpoint' => 'https://provider.test/oauth/token',
                'jwks_uri' => 'https://provider.test/oauth/jwks',
                'userinfo_endpoint' => 'https://provider.test/oauth/userinfo',
            ]),
        ),
    ]);

    app(Discovery::class)->get();
})->throws(
    ConfigurationException::class,
    'OIDC discovery issuer does not match the configured issuer.',
);

it('rejects a discovery response that is not a JSON object', function () {
    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' => Http::response([]),
    ]);

    app(Discovery::class)->get();
})->throws(
    ConfigurationException::class,
    'Invalid OIDC discovery response',
);

it('rejects a required endpoint that is not an absolute HTTP URL', function () {
    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' => Http::response(
            discoveryDocument([
                'token_endpoint' => '/oauth/token',
            ]),
        ),
    ]);

    app(Discovery::class)->get();
})->throws(
    ConfigurationException::class,
    'OIDC discovery field [token_endpoint] is not a valid URL.',
);

it('rejects a non-loopback HTTP endpoint', function () {
    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' => Http::response(
            discoveryDocument([
                'token_endpoint' => 'http://provider.test/oauth/token',
            ]),
        ),
    ]);

    app(Discovery::class)->get();
})->throws(
    ConfigurationException::class,
    'OIDC discovery field [token_endpoint] must use HTTPS.',
);

it('allows an optional end session endpoint', function () {
    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' => Http::response(
            discoveryDocument([
                'end_session_endpoint' => 'http://localhost:8000/oauth/logout',
            ]),
        ),
    ]);

    expect(app(Discovery::class)->get('end_session_endpoint'))
        ->toBe('http://localhost:8000/oauth/logout');
});
