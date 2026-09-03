<?php

use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Snairbef\Laracloak\Auth\Guard;
use Snairbef\Laracloak\Contracts\Identity;
use Snairbef\Laracloak\Contracts\Revocation;
use Snairbef\Laracloak\Contracts\UserResolver;
use Snairbef\Laracloak\Tests\Fixtures\User;

function guard(
    ?Identity $identity = null,
    ?Revocation $revocation = null,
    ?UserResolver $resolver = null,
    ?UserProvider $provider = null,
): Guard {
    return new Guard(
        'web',
        $identity ?? Mockery::mock(Identity::class),
        new Store(
            'test',
            new ArraySessionHandler(3600),
        ),
        $provider ?? Mockery::mock(UserProvider::class),
        $revocation ?? Mockery::mock(Revocation::class),
        $resolver ?? Mockery::mock(UserResolver::class),
    );
}

it('returns guest when no identity exists', function () {
    $identity = Mockery::mock(Identity::class);

    $identity
        ->shouldReceive('current')
        ->once()
        ->andReturn(null);

    $guard = guard(identity: $identity);

    expect($guard->guest())
        ->toBeTrue()
        ->and($guard->check())
        ->toBeFalse()
        ->and($guard->user())
        ->toBeNull();
});

it('resolves the authenticated user', function () {
    $identity = Mockery::mock(Identity::class);
    $revocation = Mockery::mock(Revocation::class);
    $resolver = Mockery::mock(UserResolver::class);

    $attributes = [
        'sub' => 'subject-123',
        'name' => 'Febry',
    ];

    $user = new User([
        'id' => 1,
        'sub' => 'subject-123',
        'name' => 'Febry',
    ]);

    $identity
        ->shouldReceive('current')
        ->once()
        ->andReturn($attributes);

    $identity
        ->shouldReceive('get')
        ->once()
        ->andReturn($attributes);

    $revocation
        ->shouldReceive('revoked')
        ->twice()
        ->with('subject-123')
        ->andReturnFalse();

    $resolver
        ->shouldReceive('resolve')
        ->once()
        ->with($attributes)
        ->andReturn($user);

    $guard = guard(
        identity: $identity,
        revocation: $revocation,
        resolver: $resolver,
    );

    expect($guard->check())
        ->toBeTrue()
        ->and($guard->user())
        ->toBe($user)
        ->and($guard->id())
        ->toBe(1);
});

it('clears identity when subject is revoked', function () {
    $identity = Mockery::mock(Identity::class);
    $revocation = Mockery::mock(Revocation::class);

    $identity
        ->shouldReceive('current')
        ->once()
        ->andReturn([
            'sub' => 'subject-123',
        ]);

    $revocation
        ->shouldReceive('revoked')
        ->once()
        ->with('subject-123')
        ->andReturnTrue();

    $identity
        ->shouldReceive('clear')
        ->once();

    $guard = guard(
        identity: $identity,
        revocation: $revocation,
    );

    expect($guard->user())
        ->toBeNull();
});

it('supports setUser', function () {
    $user = new User([
        'id' => 10,
        'sub' => 'subject-123',
    ]);

    $guard = guard();

    expect($guard->setUser($user))
        ->toBe($guard)
        ->and($guard->hasUser())
        ->toBeTrue()
        ->and($guard->user())
        ->toBe($user);
});

it('supports login', function () {
    $user = new User([
        'id' => 10,
        'sub' => 'subject-123',
    ]);

    $guard = guard();

    $guard->login($user);

    expect($guard->user())
        ->toBe($user);
});

it('supports login using ID', function () {
    $user = new User([
        'id' => 10,
        'sub' => 'subject-123',
    ]);

    $provider = Mockery::mock(UserProvider::class);

    $provider
        ->shouldReceive('retrieveById')
        ->once()
        ->with(10)
        ->andReturn($user);

    $guard = guard(
        provider: $provider,
    );

    expect($guard->loginUsingId(10))
        ->toBe($user)
        ->and($guard->user())
        ->toBe($user);
});

it('returns false when login using an unknown ID', function () {
    $provider = Mockery::mock(UserProvider::class);

    $provider
        ->shouldReceive('retrieveById')
        ->once()
        ->with(10)
        ->andReturn(null);

    $guard = guard(provider: $provider);

    expect($guard->loginUsingId(10))
        ->toBeFalse();
});

it('identifies itself as OIDC', function () {
    expect(guard()->oidc())
        ->toBeTrue();
});

it('does not support remember authentication', function () {
    expect(guard()->viaRemember())
        ->toBeFalse();
});
