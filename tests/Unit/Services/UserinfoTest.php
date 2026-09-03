<?php

use Illuminate\Support\Facades\Http;
use Snairbef\Laracloak\Exceptions\OidcException;
use Snairbef\Laracloak\Services\Userinfo;

it('retrieves userinfo', function () {
    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' => Http::response([
            'issuer' => 'http://localhost:8000',
            'userinfo_endpoint' => 'http://localhost:8000/oauth/userinfo',
        ]),

        'http://localhost:8000/oauth/userinfo' => Http::response([
            'sub' => 'subject-123',
            'name' => 'Febry',
            'email' => 'febry@example.com',
        ]),
    ]);

    $userinfo = app(Userinfo::class);

    expect($userinfo->get('access-token'))
        ->toMatchArray([
            'sub' => 'subject-123',
            'name' => 'Febry',
        ]);
});

it('rejects an empty access token', function () {
    app(Userinfo::class)->get('');
})->throws(
    OidcException::class,
    'OIDC access token is missing.',
);

it('rejects invalid userinfo responses', function () {
    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' => Http::response([
            'userinfo_endpoint' => 'http://localhost:8000/oauth/userinfo',
        ]),

        'http://localhost:8000/oauth/userinfo' => Http::response('invalid'),
    ]);

    app(Userinfo::class)->get('access-token');
})->throws(
    OidcException::class,
    'Invalid OIDC userinfo response.',
);
