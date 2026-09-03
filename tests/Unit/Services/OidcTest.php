<?php

use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Snairbef\Laracloak\Contracts\Discovery;
use Snairbef\Laracloak\Contracts\Jwt;
use Snairbef\Laracloak\Contracts\Pkce;
use Snairbef\Laracloak\Contracts\Revocation;
use Snairbef\Laracloak\Contracts\State;
use Snairbef\Laracloak\Contracts\Token;
use Snairbef\Laracloak\Contracts\Userinfo;
use Snairbef\Laracloak\Exceptions\OidcException;
use Snairbef\Laracloak\Services\Oidc;

function oidcRequest(): Request
{
    $request = Request::create('/');

    $session = new Store(
        'test',
        new ArraySessionHandler(3600),
    );

    $session->start();

    $request->setLaravelSession($session);

    return $request;
}

function oidcService(
    ?Discovery $discovery = null,
    ?Token $token = null,
    ?Userinfo $userinfo = null,
    ?Jwt $jwt = null,
    ?State $state = null,
    ?Pkce $pkce = null,
    ?Revocation $revocation = null,
): Oidc {
    return new Oidc(
        $discovery ?? Mockery::mock(Discovery::class),
        $token ?? Mockery::mock(Token::class),
        $userinfo ?? Mockery::mock(Userinfo::class),
        $jwt ?? Mockery::mock(Jwt::class),
        $state ?? Mockery::mock(State::class),
        $pkce ?? Mockery::mock(Pkce::class),
        $revocation ?? Mockery::mock(Revocation::class),
    );
}

it('stores login flow in session', function () {
    $request = oidcRequest();

    $state = Mockery::mock(State::class);
    $pkce = Mockery::mock(Pkce::class);
    $discovery = Mockery::mock(Discovery::class);

    $state
        ->shouldReceive('generate')
        ->twice()
        ->andReturn(
            'state-value',
            'nonce-value',
        );

    $pkce
        ->shouldReceive('generate')
        ->once()
        ->andReturn('verifier');

    $pkce
        ->shouldReceive('challenge')
        ->once()
        ->with('verifier')
        ->andReturn('challenge');

    $discovery
        ->shouldReceive('get')
        ->once()
        ->with('authorization_endpoint')
        ->andReturn(
            'http://localhost/oauth/authorize',
        );

    $response = oidcService(
        discovery: $discovery,
        state: $state,
        pkce: $pkce,
    )->login($request);

    expect($response->getTargetUrl())
        ->toContain(
            'http://localhost/oauth/authorize?',
        );

    expect($request->session()->get('laracloak.flow'))
        ->toMatchArray([
            'state' => 'state-value',
            'nonce' => 'nonce-value',
            'verifier' => 'verifier',
        ]);
});

it('rejects an invalid callback state', function () {
    $request = oidcRequest();

    $request->query->set('state', 'wrong');
    $request->query->set('code', 'code');

    $request->session()->put(
        'laracloak.flow',
        [
            'state' => 'expected',
            'nonce' => 'nonce',
            'verifier' => 'verifier',
        ],
    );

    oidcService()->callback($request);
})->throws(
    OidcException::class,
    'Invalid OIDC state.',
);

it('rejects a missing authorization code', function () {
    $request = oidcRequest();

    $request->query->set('state', 'expected');

    $request->session()->put(
        'laracloak.flow',
        [
            'state' => 'expected',
            'nonce' => 'nonce',
            'verifier' => 'verifier',
        ],
    );

    oidcService()->callback($request);
})->throws(
    OidcException::class,
    'OIDC authorization code is missing.',
);

it('rejects an OIDC error callback', function () {
    $request = oidcRequest();

    $request->query->set(
        'error',
        'access_denied',
    );

    oidcService()->callback($request);
})->throws(
    OidcException::class,
    'OIDC authentication failed.',
);

it('returns the current user from session', function () {
    $request = oidcRequest();

    $request->session()->put(
        'laracloak.user',
        [
            'sub' => 'subject-123',
            'name' => 'Febry',
        ],
    );

    expect(
        oidcService()->user($request),
    )->toMatchArray([
        'sub' => 'subject-123',
    ]);
});

it('returns tokens from session', function () {
    $request = oidcRequest();

    $request->session()->put(
        'laracloak.token',
        [
            'access_token' => 'access-token',
        ],
    );

    expect(
        oidcService()->tokens($request),
    )->toMatchArray([
        'access_token' => 'access-token',
    ]);
});

it('revokes the subject during back-channel logout', function () {
    $jwt = Mockery::mock(Jwt::class);
    $revocation = Mockery::mock(Revocation::class);

    $jwt
        ->shouldReceive('logout')
        ->once()
        ->with('logout-token')
        ->andReturn([
            'sub' => 'subject-123',
        ]);

    $revocation
        ->shouldReceive('revoke')
        ->once()
        ->with('subject-123');

    oidcService(
        jwt: $jwt,
        revocation: $revocation,
    )->backchannel('logout-token');
});

it('rejects an invalid back-channel logout token', function () {
    oidcService()->backchannel(null);
})->throws(
    OidcException::class,
    'OIDC logout token is missing.',
);
