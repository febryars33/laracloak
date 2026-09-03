<?php

use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Snairbef\Laracloak\Contracts\Token;
use Snairbef\Laracloak\Contracts\Userinfo;
use Snairbef\Laracloak\Exceptions\OidcException;
use Snairbef\Laracloak\Services\Identity;

function identitySession(): Store
{
    $session = new Store(
        'test',
        new ArraySessionHandler(3600),
    );

    $session->start();

    return $session;
}

it('returns the current identity', function () {
    $session = identitySession();

    $session->put(
        'laracloak.user',
        [
            'sub' => 'subject-123',
            'name' => 'Febry',
        ],
    );

    $identity = new Identity(
        $session,
        Mockery::mock(Userinfo::class),
        Mockery::mock(Token::class),
    );

    expect($identity->current())
        ->toMatchArray([
            'sub' => 'subject-123',
        ]);
});

it('returns null without an identity', function () {
    $identity = new Identity(
        identitySession(),
        Mockery::mock(Userinfo::class),
        Mockery::mock(Token::class),
    );

    expect($identity->current())
        ->toBeNull();
});

it('clears the identity', function () {
    $session = identitySession();

    $session->put(
        'laracloak.user',
        ['sub' => 'subject-123'],
    );

    $session->put(
        'laracloak.identity_at',
        now()->timestamp,
    );

    $identity = new Identity(
        $session,
        Mockery::mock(Userinfo::class),
        Mockery::mock(Token::class),
    );

    $identity->clear();

    expect($session->get('laracloak.user'))
        ->toBeNull()
        ->and($session->get('laracloak.identity_at'))
        ->toBeNull();
});

it('refreshes stale identity', function () {
    $session = identitySession();

    $session->put(
        'laracloak.user',
        [
            'sub' => 'subject-123',
            'name' => 'Old',
        ],
    );

    $session->put(
        'laracloak.identity_at',
        now()->subMinute()->timestamp,
    );

    $userinfo = Mockery::mock(Userinfo::class);
    $token = Mockery::mock(Token::class);

    $token
        ->shouldReceive('access')
        ->once()
        ->andReturn('access-token');

    $userinfo
        ->shouldReceive('get')
        ->once()
        ->with('access-token')
        ->andReturn([
            'sub' => 'subject-123',
            'name' => 'New',
        ]);

    $identity = new Identity(
        $session,
        $userinfo,
        $token,
    );

    expect($identity->get())
        ->toMatchArray([
            'sub' => 'subject-123',
            'name' => 'New',
        ]);
});

it('rejects subject changes during synchronization', function () {
    $session = identitySession();

    $session->put(
        'laracloak.user',
        [
            'sub' => 'subject-123',
        ],
    );

    $session->put(
        'laracloak.identity_at',
        now()->subMinute()->timestamp,
    );

    $token = Mockery::mock(Token::class);
    $userinfo = Mockery::mock(Userinfo::class);

    $token
        ->shouldReceive('access')
        ->once()
        ->andReturn('access-token');

    $userinfo
        ->shouldReceive('get')
        ->once()
        ->andReturn([
            'sub' => 'subject-456',
        ]);

    $identity = new Identity(
        $session,
        $userinfo,
        $token,
    );

    $identity->get();
})->throws(
    OidcException::class,
    'OIDC subject mismatch.',
);
