<?php

use Snairbef\Laracloak\Support\Pkce;

it('generates a valid code verifier', function () {
    $pkce = new Pkce;

    $verifier = $pkce->generate();

    expect($verifier)
        ->toBeString()
        ->not->toBeEmpty()
        ->toMatch('/^[A-Za-z0-9_-]+$/');
});

it('generates an S256 challenge', function () {
    $pkce = new Pkce;

    $verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    expect($pkce->challenge($verifier))
        ->toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
});

it('generates different verifiers', function () {
    $pkce = new Pkce;

    expect($pkce->generate())
        ->not->toBe($pkce->generate());
});
