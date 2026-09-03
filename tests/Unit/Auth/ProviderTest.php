<?php

use Illuminate\Contracts\Auth\Authenticatable;
use Snairbef\Laracloak\Auth\Provider;
use Snairbef\Laracloak\Contracts\Identity;

it('retrieves a user by matching subject', function () {
    $identity = Mockery::mock(Identity::class);

    $identity
        ->shouldReceive('get')
        ->once()
        ->andReturn([
            'sub' => 'subject-123',
            'name' => 'Febry',
        ]);

    $provider = new Provider($identity);

    $user = $provider->retrieveById('subject-123');

    expect($user)
        ->not->toBeNull()
        ->and($user->getAuthIdentifier())
        ->toBe('subject-123')
        ->and($user->name)
        ->toBe('Febry');
});

it('returns null for a non matching subject', function () {
    $identity = Mockery::mock(Identity::class);

    $identity
        ->shouldReceive('get')
        ->once()
        ->andReturn([
            'sub' => 'subject-123',
        ]);

    $provider = new Provider($identity);

    expect($provider->retrieveById('subject-456'))
        ->toBeNull();
});

it('returns null without identity', function () {
    $identity = Mockery::mock(Identity::class);

    $identity
        ->shouldReceive('get')
        ->once()
        ->andReturn(null);

    $provider = new Provider($identity);

    expect($provider->retrieveById('subject-123'))
        ->toBeNull();
});

it('does not support token retrieval', function () {
    $provider = new Provider(
        Mockery::mock(Identity::class),
    );

    expect(
        $provider->retrieveByToken('id', 'token'),
    )->toBeNull();
});

it('does not support credential retrieval', function () {
    $provider = new Provider(
        Mockery::mock(Identity::class),
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
