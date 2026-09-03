<?php

use Illuminate\Support\Facades\Http;
use Snairbef\Laracloak\Exceptions\OidcException;
use Snairbef\Laracloak\Http\Client;

it('rejects empty URLs', function () {
    $client = new Client;

    $client->get('');
})->throws(
    InvalidArgumentException::class,
    'Laracloak HTTP request URL cannot be empty.',
);

it('rejects relative URLs', function () {
    $client = new Client;

    $client->get('/oauth/token');
})->throws(
    InvalidArgumentException::class,
    'Laracloak HTTP request URL must be absolute: /oauth/token',
);

it('sends GET requests', function () {
    Http::fake([
        'https://provider.test/*' => Http::response([
            'ok' => true,
        ]),
    ]);

    $client = new Client;

    $response = $client->get(
        'https://provider.test/test',
    );

    expect($response->json())
        ->toBe(['ok' => true]);

    Http::assertSent(function ($request) {
        return $request->method() === 'GET'
            && $request->url() === 'https://provider.test/test';
    });
});

it('sends bearer requests', function () {
    Http::fake([
        'https://provider.test/*' => Http::response([
            'sub' => '123',
        ]),
    ]);

    $client = new Client;

    $response = $client->bearer(
        'https://provider.test/userinfo',
        'access-token',
    );

    expect($response->json())
        ->toBe(['sub' => '123']);

    Http::assertSent(function ($request) {
        return $request->hasHeader(
            'Authorization',
            'Bearer access-token',
        );
    });
});

it('sends form POST requests', function () {
    Http::fake([
        'https://provider.test/*' => Http::response([
            'access_token' => 'token',
        ]),
    ]);

    $client = new Client;

    $client->post(
        'https://provider.test/oauth/token',
        [
            'grant_type' => 'authorization_code',
        ],
    );

    Http::assertSent(function ($request) {
        return $request->method() === 'POST'
            && $request['grant_type'] === 'authorization_code';
    });
});

it('throws OIDC exceptions for failed HTTP responses', function () {
    Http::fake([
        'https://provider.test/*' => Http::response([], 401),
    ]);

    $client = new Client;

    $client->get('https://provider.test/test');
})->throws(OidcException::class);
