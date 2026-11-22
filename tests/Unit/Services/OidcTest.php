<?php

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Snairbef\Laracloak\Contracts\Discovery;
use Snairbef\Laracloak\Contracts\Jwt;
use Snairbef\Laracloak\Contracts\Pkce;
use Snairbef\Laracloak\Contracts\Replay;
use Snairbef\Laracloak\Contracts\Revocation;
use Snairbef\Laracloak\Contracts\State;
use Snairbef\Laracloak\Contracts\Token;
use Snairbef\Laracloak\Contracts\Userinfo;
use Snairbef\Laracloak\Exceptions\AuthenticationException;
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
    ?Replay $replay = null,
    ?State $state = null,
    ?Pkce $pkce = null,
    ?Revocation $revocation = null,
): Oidc {
    return new Oidc(
        $discovery ?? Mockery::mock(Discovery::class),
        $token ?? Mockery::mock(Token::class),
        $userinfo ?? Mockery::mock(Userinfo::class),
        $jwt ?? Mockery::mock(Jwt::class),
        $replay ?? Mockery::mock(Replay::class),
        $state ?? Mockery::mock(State::class),
        $pkce ?? Mockery::mock(Pkce::class),
        $revocation ?? Mockery::mock(Revocation::class),
    );
}

function oidcReplay(
    string $id,
    bool $process = true,
): Replay {
    $replay = Mockery::mock(Replay::class);

    $replay
        ->shouldReceive('once')
        ->once()
        ->with($id, Mockery::type('int'), Mockery::type(Closure::class))
        ->andReturnUsing(function (
            string $id,
            int $expires,
            Closure $callback,
        ) use ($process): bool {
            if ($process) {
                $callback();
            }

            return $process;
        });

    return $replay;
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

    $flow = $request->session()->get('laracloak.flow.state-value');

    expect($flow['state'])
        ->toBe('state-value')
        ->and($flow['nonce'])
        ->toBe('nonce-value')
        ->and($flow['verifier'])
        ->toBe('verifier')
        ->and($flow['expires_at'])
        ->toBeGreaterThan(now()->timestamp);
});

it('retains concurrent login flows in session', function () {
    $request = oidcRequest();
    $request->session()->put('laracloak.flow', [
        'existing-state' => [
            'state' => 'existing-state',
            'nonce' => 'existing-nonce',
            'verifier' => 'existing-verifier',
            'expires_at' => now()->addMinutes(5)->timestamp,
        ],
    ]);

    $state = Mockery::mock(State::class);
    $pkce = Mockery::mock(Pkce::class);
    $discovery = Mockery::mock(Discovery::class);

    $state
        ->shouldReceive('generate')
        ->twice()
        ->andReturn('new-state', 'new-nonce');
    $pkce
        ->shouldReceive('generate')
        ->once()
        ->andReturn('new-verifier');
    $pkce
        ->shouldReceive('challenge')
        ->once()
        ->andReturn('challenge');
    $discovery
        ->shouldReceive('get')
        ->once()
        ->with('authorization_endpoint')
        ->andReturn('http://localhost/oauth/authorize');

    oidcService(
        discovery: $discovery,
        state: $state,
        pkce: $pkce,
    )->login($request);

    expect(array_keys($request->session()->get('laracloak.flow')))
        ->toContain('existing-state', 'new-state');
});

it('rejects an invalid callback state', function () {
    $request = oidcRequest();

    $request->query->set('state', 'wrong');
    $request->query->set('code', 'code');

    $request->session()->put(
        'laracloak.flow',
        [
            'expected' => [
                'state' => 'expected',
                'nonce' => 'nonce',
                'verifier' => 'verifier',
                'expires_at' => now()->addMinutes(5)->timestamp,
            ],
        ],
    );

    oidcService()->callback($request);
})->throws(
    AuthenticationException::class,
    'Invalid OIDC state.',
);

it('rejects a missing authorization code', function () {
    $request = oidcRequest();

    $request->query->set('state', 'expected');

    $request->session()->put(
        'laracloak.flow',
        [
            'expected' => [
                'state' => 'expected',
                'nonce' => 'nonce',
                'verifier' => 'verifier',
                'expires_at' => now()->addMinutes(5)->timestamp,
            ],
        ],
    );

    oidcService()->callback($request);
})->throws(
    AuthenticationException::class,
    'OIDC authorization code is missing.',
);

it('rejects an OIDC error callback', function () {
    $request = oidcRequest();

    $request->query->set(
        'error',
        'access_denied',
    );
    $request->query->set('state', 'expected');
    $request->session()->put('laracloak.flow', [
        'expected' => [
            'state' => 'expected',
            'nonce' => 'nonce',
            'verifier' => 'verifier',
            'expires_at' => now()->addMinutes(5)->timestamp,
        ],
    ]);

    oidcService()->callback($request);
})->throws(
    AuthenticationException::class,
    'OIDC authentication failed.',
);

it('does not consume a login flow for an error callback with invalid state', function () {
    $request = oidcRequest();
    $request->query->set('error', 'access_denied');
    $request->query->set('state', 'wrong');
    $flow = [
        'expected' => [
            'state' => 'expected',
            'nonce' => 'nonce',
            'verifier' => 'verifier',
            'expires_at' => now()->addMinutes(5)->timestamp,
        ],
    ];
    $request->session()->put('laracloak.flow', $flow);

    expect(fn () => oidcService()->callback($request))
        ->toThrow(AuthenticationException::class, 'Invalid OIDC state.');

    expect($request->session()->get('laracloak.flow'))->toBe($flow);
});

it('rejects an expired login flow', function () {
    $request = oidcRequest();
    $request->query->set('state', 'expected');
    $request->query->set('code', 'authorization-code');
    $request->session()->put('laracloak.flow', [
        'expected' => [
            'state' => 'expected',
            'nonce' => 'nonce',
            'verifier' => 'verifier',
            'expires_at' => now()->subSecond()->timestamp,
        ],
    ]);

    expect(fn () => oidcService()->callback($request))
        ->toThrow(
            AuthenticationException::class,
            'OIDC authentication session has expired.',
        );

    expect($request->session()->has('laracloak.flow'))->toBeFalse();
});

it('regenerates the session after login and retains other flows', function () {
    $request = oidcRequest();
    $request->query->set('state', 'current-state');
    $request->query->set('code', 'authorization-code');
    $request->session()->put('laracloak.flow', [
        'current-state' => [
            'id' => 'current-flow',
            'state' => 'current-state',
            'nonce' => 'current-nonce',
            'verifier' => 'current-verifier',
            'expires_at' => now()->addMinutes(5)->timestamp,
        ],
        'other-state' => [
            'id' => 'other-flow',
            'state' => 'other-state',
            'nonce' => 'other-nonce',
            'verifier' => 'other-verifier',
            'expires_at' => now()->addMinutes(5)->timestamp,
        ],
    ]);

    $id = $request->session()->getId();
    $token = Mockery::mock(Token::class);
    $jwt = Mockery::mock(Jwt::class);
    $userinfo = Mockery::mock(Userinfo::class);
    $revocation = Mockery::mock(Revocation::class);

    $token
        ->shouldReceive('exchange')
        ->once()
        ->with('authorization-code', 'current-verifier')
        ->andReturn([
            'id_token' => 'id-token',
            'access_token' => 'access-token',
        ]);
    $jwt
        ->shouldReceive('validate')
        ->once()
        ->with('id-token')
        ->andReturn((object) [
            'sub' => 'subject-123',
            'nonce' => 'current-nonce',
            'sid' => 'session-123',
        ]);
    $userinfo
        ->shouldReceive('get')
        ->once()
        ->with('access-token')
        ->andReturn(['sub' => 'subject-123', 'name' => 'Febry']);
    $revocation
        ->shouldReceive('clear')
        ->once()
        ->with('session-123');
    $revocation
        ->shouldReceive('clear')
        ->once()
        ->with('subject-123');
    $revocation
        ->shouldReceive('clear')
        ->once()
        ->with('legacy:subject-123');

    $response = oidcService(
        token: $token,
        userinfo: $userinfo,
        jwt: $jwt,
        revocation: $revocation,
    )->callback($request);

    expect($response)
        ->toBeInstanceOf(RedirectResponse::class)
        ->and($request->session()->getId())
        ->not->toBe($id)
        ->and(array_keys($request->session()->get('laracloak.flow')))
        ->toBe(['other-state'])
        ->and($request->session()->get('laracloak.user.sub'))
        ->toBe('subject-123');
});

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
            'jti' => 'logout-1',
            'exp' => now()->addMinutes(2)->timestamp,
        ]);

    $replay = oidcReplay('logout-1');

    $revocation
        ->shouldReceive('revoke')
        ->once()
        ->with('subject-123');

    $revocation
        ->shouldReceive('revoke')
        ->once()
        ->with('legacy:subject-123');

    oidcService(
        jwt: $jwt,
        replay: $replay,
        revocation: $revocation,
    )->backchannel('logout-token');
});

it('revokes the sid during back-channel logout', function () {
    $jwt = Mockery::mock(Jwt::class);
    $revocation = Mockery::mock(Revocation::class);

    $jwt
        ->shouldReceive('logout')
        ->once()
        ->with('logout-token')
        ->andReturn([
            'sub' => 'subject-123',
            'sid' => 'session-device-1',
            'jti' => 'logout-2',
            'exp' => now()->addMinutes(2)->timestamp,
        ]);

    $replay = oidcReplay('logout-2');

    $revocation
        ->shouldReceive('revoke')
        ->once()
        ->with('session-device-1');

    oidcService(
        jwt: $jwt,
        replay: $replay,
        revocation: $revocation,
    )->backchannel('logout-token');
});

it('revokes only the sid during back-channel logout when sub is missing', function () {
    $jwt = Mockery::mock(Jwt::class);
    $revocation = Mockery::mock(Revocation::class);

    $jwt
        ->shouldReceive('logout')
        ->once()
        ->with('logout-token')
        ->andReturn([
            'sid' => 'session-device-1',
            'jti' => 'logout-3',
            'exp' => now()->addMinutes(2)->timestamp,
        ]);

    $replay = oidcReplay('logout-3');

    $revocation
        ->shouldReceive('revoke')
        ->once()
        ->with('session-device-1');

    oidcService(
        jwt: $jwt,
        replay: $replay,
        revocation: $revocation,
    )->backchannel('logout-token');
});

it('does not revoke a session again when a logout token is replayed', function () {
    $jwt = Mockery::mock(Jwt::class);
    $replay = oidcReplay('logout-replayed', false);
    $revocation = Mockery::mock(Revocation::class);

    $jwt
        ->shouldReceive('logout')
        ->once()
        ->with('logout-token')
        ->andReturn([
            'sid' => 'session-device-1',
            'jti' => 'logout-replayed',
            'exp' => now()->addMinutes(2)->timestamp,
        ]);

    oidcService(
        jwt: $jwt,
        replay: $replay,
        revocation: $revocation,
    )->backchannel('logout-token');
});

it('rejects an invalid back-channel logout token', function () {
    oidcService()->backchannel(null);
})->throws(
    AuthenticationException::class,
    'OIDC logout token is missing.',
);
