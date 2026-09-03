<?php

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Snairbef\Laracloak\Exceptions\OidcException;
use Snairbef\Laracloak\Http\Client;
use Snairbef\Laracloak\Services\Discovery;

beforeEach(function () {
    Cache::flush();
});

it('loads OIDC discovery metadata', function () {
    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' =>
        Http::response([
            'issuer' => 'http://localhost:8000',
            'authorization_endpoint' =>
            'http://localhost:8000/oauth/authorize',
        ]),
    ]);

    $discovery = app(Discovery::class);

    expect($discovery->get())
        ->toMatchArray([
            'issuer' => 'http://localhost:8000',
        ]);
});

it('returns a specific discovery field', function () {
    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' =>
        Http::response([
            'issuer' => 'http://localhost:8000',
            'userinfo_endpoint' =>
            'http://localhost:8000/oauth/userinfo',
        ]),
    ]);

    $discovery = app(Discovery::class);

    expect($discovery->get('userinfo_endpoint'))
        ->toBe('http://localhost:8000/oauth/userinfo');
});

it('caches discovery metadata', function () {
    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' =>
        Http::response([
            'issuer' => 'http://localhost:8000',
        ]),
    ]);

    $discovery = app(Discovery::class);

    $discovery->get();
    $discovery->get();

    Http::assertSentCount(1);
});

it('throws when a discovery field is missing', function () {
    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' =>
        Http::response([
            'issuer' => 'http://localhost:8000',
        ]),
    ]);

    app(Discovery::class)->get('userinfo_endpoint');
})->throws(
    OidcException::class,
    'OIDC discovery field [userinfo_endpoint] is missing.',
);

it('rejects an invalid issuer', function () {
    config()->set(
        'laracloak.issuer',
        'invalid',
    );

    app(Discovery::class)->get();
})->throws(
    OidcException::class,
    'Invalid OIDC issuer: invalid',
);
