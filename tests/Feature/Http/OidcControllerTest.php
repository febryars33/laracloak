<?php

use Illuminate\Support\Facades\Route;
use Snairbef\Laracloak\Contracts\Oidc;
use Snairbef\Laracloak\Exceptions\OidcException;
use Snairbef\Laracloak\Http\Controllers\OidcController;

beforeEach(function () {
    Route::get(
        '/test/login',
        [OidcController::class, 'login'],
    );

    Route::get(
        '/test/callback',
        [OidcController::class, 'callback'],
    );

    Route::post(
        '/test/logout',
        [OidcController::class, 'logout'],
    );

    Route::post(
        '/test/backchannel',
        [OidcController::class, 'backchannel'],
    );
});

it('delegates login to the OIDC service', function () {
    $oidc = Mockery::mock(Oidc::class);

    $oidc
        ->shouldReceive('login')
        ->once()
        ->andReturn(
            redirect('https://provider.test/oauth/authorize'),
        );

    app()->instance(Oidc::class, $oidc);

    $this->get('/test/login')
        ->assertRedirect(
            'https://provider.test/oauth/authorize',
        );
});

it('delegates callback to the OIDC service', function () {
    $oidc = Mockery::mock(Oidc::class);

    $oidc
        ->shouldReceive('callback')
        ->once()
        ->andReturn(
            redirect('/dashboard'),
        );

    app()->instance(Oidc::class, $oidc);

    $this->get('/test/callback')
        ->assertRedirect('/dashboard');
});

it('delegates logout to the OIDC service', function () {
    $oidc = Mockery::mock(Oidc::class);

    $oidc
        ->shouldReceive('logout')
        ->once()
        ->andReturn(
            redirect('/'),
        );

    app()->instance(Oidc::class, $oidc);

    $this->post('/test/logout')
        ->assertRedirect('/');
});

it('accepts valid back-channel logout requests', function (): void {
    $oidc = Mockery::mock(Oidc::class);

    $oidc->shouldReceive('backchannel')
        ->once()
        ->with('logout-token');

    $this->app->instance(
        Oidc::class,
        $oidc,
    );

    $this->post('/test/backchannel', [
        'logout_token' => 'logout-token',
    ])
        ->assertOk()
        ->assertExactJson([]);
});

it('returns 200 for rejected back-channel logout requests', function (): void {
    $oidc = Mockery::mock(Oidc::class);

    $oidc->shouldReceive('backchannel')
        ->once()
        ->with('invalid')
        ->andThrow(
            OidcException::authentication(
                'Invalid OIDC logout token.',
            ),
        );

    $this->app->instance(
        Oidc::class,
        $oidc,
    );

    $this->post('/test/backchannel', [
        'logout_token' => 'invalid',
    ])
        ->assertOk()
        ->assertExactJson([]);
});
