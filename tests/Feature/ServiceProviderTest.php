<?php

use Illuminate\Support\Facades\Auth;
use Snairbef\Laracloak\Auth\Guard;
use Snairbef\Laracloak\Auth\Provider;
use Snairbef\Laracloak\Services\Discovery;
use Snairbef\Laracloak\Services\Identity;
use Snairbef\Laracloak\Services\Jwt;
use Snairbef\Laracloak\Services\Oidc;
use Snairbef\Laracloak\Services\Revocation;
use Snairbef\Laracloak\Services\Token;
use Snairbef\Laracloak\Services\Userinfo;
use Snairbef\Laracloak\Support\Pkce;
use Snairbef\Laracloak\Support\State;

it('registers all package services', function () {
    expect(app(Discovery::class))
        ->toBeInstanceOf(Discovery::class);

    expect(app(Token::class))
        ->toBeInstanceOf(Token::class);

    expect(app(Userinfo::class))
        ->toBeInstanceOf(Userinfo::class);

    expect(app(Jwt::class))
        ->toBeInstanceOf(Jwt::class);

    expect(app(Identity::class))
        ->toBeInstanceOf(Identity::class);

    expect(app(Revocation::class))
        ->toBeInstanceOf(Revocation::class);

    expect(app(State::class))
        ->toBeInstanceOf(State::class);

    expect(app(Pkce::class))
        ->toBeInstanceOf(Pkce::class);

    expect(app(Oidc::class))
        ->toBeInstanceOf(Oidc::class);
});

it('registers the laracloak guard', function () {
    $guard = Auth::guard('laracloak');

    expect($guard)
        ->toBeInstanceOf(Guard::class)
        ->and($guard->oidc())
        ->toBeTrue();
});

it('registers the laracloak provider', function () {
    $provider = Auth::createUserProvider('laracloak');

    expect($provider)
        ->toBeInstanceOf(Provider::class);
});

it('uses the native auth redirect callback', function () {
    expect(route('laracloak.login'))
        ->toBe(
            config('app.url').'/auth/login',
        );
});
