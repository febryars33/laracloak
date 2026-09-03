<?php

use Illuminate\Database\Eloquent\Model;
use Snairbef\Laracloak\Auth\UserResolver;
use Snairbef\Laracloak\Exceptions\OidcException;
use Snairbef\Laracloak\Tests\Fixtures\User;

beforeEach(function () {
    config()->set(
        'laracloak.user.model',
        User::class,
    );

    config()->set(
        'laracloak.user.provision',
        true,
    );
});

it('provisions a user from OIDC attributes', function () {
    $resolver = new UserResolver;

    $user = $resolver->resolve([
        'sub' => 'subject-123',
        'name' => 'Febry',
        'email' => 'febry@example.com',
    ]);

    expect($user)
        ->toBeInstanceOf(User::class)
        ->and($user->sub)
        ->toBe('subject-123')
        ->and($user->name)
        ->toBe('Febry')
        ->and($user->email)
        ->toBe('febry@example.com');

    expect(User::query()->count())
        ->toBe(1);
});

it('returns null when subject is missing', function () {
    $resolver = new UserResolver;

    expect($resolver->resolve([
        'name' => 'Febry',
    ]))->toBeNull();
});

it('returns existing users instead of creating duplicates', function () {
    User::query()->create([
        'sub' => 'subject-123',
        'name' => 'Old Name',
        'email' => 'old@example.com',
    ]);

    $resolver = new UserResolver;

    $user = $resolver->resolve([
        'sub' => 'subject-123',
        'name' => 'New Name',
        'email' => 'new@example.com',
    ]);

    expect(User::query()->count())
        ->toBe(1)
        ->and($user->name)
        ->toBe('New Name')
        ->and($user->email)
        ->toBe('new@example.com');
});

it('does not provision when disabled', function () {
    config()->set(
        'laracloak.user.provision',
        false,
    );

    $resolver = new UserResolver;

    expect($resolver->resolve([
        'sub' => 'subject-123',
        'name' => 'Febry',
    ]))->toBeNull();

    expect(User::query()->count())
        ->toBe(0);
});

it('does not overwrite attributes with null values', function () {
    User::query()->create([
        'sub' => 'subject-123',
        'name' => 'Existing',
        'email' => 'existing@example.com',
    ]);

    $resolver = new UserResolver;

    $resolver->resolve([
        'sub' => 'subject-123',
        'name' => null,
        'email' => null,
    ]);

    $user = User::query()->first();

    expect($user->name)
        ->toBe('Existing')
        ->and($user->email)
        ->toBe('existing@example.com');
});

it('rejects an invalid user model', function () {
    config()->set(
        'laracloak.user.model',
        stdClass::class,
    );

    $resolver = new UserResolver;

    $resolver->resolve([
        'sub' => 'subject-123',
    ]);
})->throws(
    RuntimeException::class,
    'Laracloak user model must extend an Eloquent Authenticatable model.',
);
