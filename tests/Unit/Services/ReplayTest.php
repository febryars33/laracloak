<?php

use Snairbef\Laracloak\Services\Replay;

it('processes a logout token only once', function () {
    config([
        'laracloak.issuer' => 'https://issuer.example',
        'laracloak.client.id' => 'client-123',
    ]);

    $replay = new Replay;
    $processed = 0;

    $first = $replay->once(
        'token-123',
        now()->addMinutes(2)->timestamp,
        function () use (&$processed): void {
            $processed++;
        },
    );

    $second = $replay->once(
        'token-123',
        now()->addMinutes(2)->timestamp,
        function () use (&$processed): void {
            $processed++;
        },
    );

    expect([$first, $second, $processed])
        ->toBe([true, false, 1]);
});

it('allows retrying a logout token when its processing fails', function () {
    config([
        'laracloak.issuer' => 'https://issuer.example',
        'laracloak.client.id' => 'client-456',
    ]);

    $replay = new Replay;
    $expires = now()->addMinutes(2)->timestamp;

    expect(fn () => $replay->once(
        'token-456',
        $expires,
        fn () => throw new RuntimeException('Revocation storage failed.'),
    ))->toThrow(RuntimeException::class, 'Revocation storage failed.');

    expect($replay->once(
        'token-456',
        $expires,
        fn () => null,
    ))->toBeTrue();
});
