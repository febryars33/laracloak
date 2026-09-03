<?php

use Snairbef\Laracloak\Support\State;

it('generates a cryptographically random state', function () {
    $state = new State;

    $value = $state->generate();

    expect($value)
        ->toBeString()
        ->toHaveLength(64)
        ->toMatch('/^[a-f0-9]+$/');
});

it('generates unique states', function () {
    $state = new State;

    expect($state->generate())
        ->not->toBe($state->generate());
});
