<?php

use Snairbef\Laracloak\Models\User;

it('uses sub as the authentication identifier', function () {
    $user = new User([
        'sub' => 'subject-123',
        'name' => 'Febry',
    ]);

    expect($user->getAuthIdentifierName())
        ->toBe('sub')
        ->and($user->getAuthIdentifier())
        ->toBe('subject-123');
});

it('supports dynamic attributes', function () {
    $user = new User([
        'sub' => 'subject-123',
    ]);

    $user->name = 'Febry';

    expect($user->name)
        ->toBe('Febry');
});

it('supports array access', function () {
    $user = new User([
        'sub' => 'subject-123',
    ]);

    $user['name'] = 'Febry';

    expect($user['name'])
        ->toBe('Febry')
        ->and(isset($user['sub']))
        ->toBeTrue();
});

it('serializes to an array', function () {
    $user = new User([
        'sub' => 'subject-123',
        'name' => 'Febry',
    ]);

    expect($user->toArray())
        ->toMatchArray([
            'sub' => 'subject-123',
            'name' => 'Febry',
        ]);
});

it('returns selected attributes', function () {
    $user = new User([
        'sub' => 'subject-123',
        'name' => 'Febry',
        'email' => 'febry@example.com',
    ]);

    expect($user->only([
        'sub',
        'email',
    ]))->toBe([
        'sub' => 'subject-123',
        'email' => 'febry@example.com',
    ]);
});
