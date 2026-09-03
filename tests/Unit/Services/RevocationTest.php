<?php

use Illuminate\Support\Facades\Cache;
use Snairbef\Laracloak\Services\Revocation;

it('revokes a subject', function () {
    $revocation = new Revocation;

    $revocation->revoke('subject-123');

    expect($revocation->revoked('subject-123'))
        ->toBeTrue();
});

it('does not revoke another subject', function () {
    $revocation = new Revocation;

    $revocation->revoke('subject-123');

    expect($revocation->revoked('subject-456'))
        ->toBeFalse();
});

it('clears a revoked subject', function () {
    $revocation = new Revocation;

    $revocation->revoke('subject-123');

    $revocation->clear('subject-123');

    expect($revocation->revoked('subject-123'))
        ->toBeFalse();
});

it('stores revocations in the expected cache namespace', function () {
    $revocation = new Revocation;

    $revocation->revoke('subject-123');

    expect(Cache::has(
        'laracloak.logout.'.sha1('subject-123'),
    ))->toBeTrue();
});
