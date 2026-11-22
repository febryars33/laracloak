<?php

use Illuminate\Contracts\Auth\Authenticatable;
use Snairbef\Laracloak\Auth\Provider;
use Snairbef\Laracloak\Contracts\Identity;
use Snairbef\Laracloak\Contracts\UserResolver;
use Snairbef\Laracloak\Models\User;

it('retrieves the local user by its primary key', function () {
    $identity = Mockery::mock(Identity::class);
    $resolver = Mockery::mock(UserResolver::class);
    $attributes = [
        'sub' => 'subject-123',
        'name' => 'Febry',
    ];
    $user = new User([
        'id' => 25,
        ...$attributes,
    ]);

    $identity
        ->shouldReceive('get')
        ->once()
        ->andReturn($attributes);

    $resolver
        ->shouldReceive('resolve')
        ->once()
        ->with($attributes)
        ->andReturn($user);

    $provider = new Provider($identity, $resolver);

    $retrieved = $provider->retrieveById(25);

    expect($retrieved)
        ->not->toBeNull()
        ->toBe($user)
        ->and($retrieved->getAuthIdentifier())
        ->toBe(25)
        ->and($retrieved->name)
        ->toBe('Febry');
});

it('does not confuse the provider subject for a local user ID', function () {
    $identity = Mockery::mock(Identity::class);
    $resolver = Mockery::mock(UserResolver::class);
    $attributes = ['sub' => 'subject-123'];

    $identity
        ->shouldReceive('get')
        ->once()
        ->andReturn($attributes);

    $resolver
        ->shouldReceive('resolve')
        ->once()
        ->with($attributes)
        ->andReturn(new User([
            'id' => 25,
            'sub' => 'subject-123',
        ]));

    $provider = new Provider($identity, $resolver);

    expect($provider->retrieveById('subject-123'))
        ->toBeNull();
});

it('returns null without identity', function () {
    $identity = Mockery::mock(Identity::class);
    $resolver = Mockery::mock(UserResolver::class);

    $identity
        ->shouldReceive('get')
        ->once()
        ->andReturn(null);

    $provider = new Provider($identity, $resolver);

    expect($provider->retrieveById('subject-123'))
        ->toBeNull();
});

it('does not support token retrieval', function () {
    $provider = new Provider(
        Mockery::mock(Identity::class),
        Mockery::mock(UserResolver::class),
    );

    expect(
        $provider->retrieveByToken('id', 'token'),
    )->toBeNull();
});

it('does not support credential retrieval', function () {
    $provider = new Provider(
        Mockery::mock(Identity::class),
        Mockery::mock(UserResolver::class),
    );

    expect(
        $provider->retrieveByCredentials([
            'email' => 'test@example.com',
        ]),
    )->toBeNull();
});

it('does not validate credentials', function () {
    $provider = new Provider(
        Mockery::mock(Identity::class),
        Mockery::mock(UserResolver::class),
    );

    expect(
        $provider->validateCredentials(
            Mockery::mock(
                Authenticatable::class,
            ),
            [],
        ),
    )->toBeFalse();
});
