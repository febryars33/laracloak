<?php

use Illuminate\Support\Facades\Route;
use Snairbef\Laracloak\Http\Controllers\OidcController;

Route::middleware('web')->group(function () {
    Route::get(
        '/auth/login',
        [OidcController::class, 'login']
    )->name('laracloak.login');

    Route::get(
        '/auth/callback',
        [OidcController::class, 'callback']
    )->name('laracloak.callback');

    Route::post(
        '/auth/logout',
        [OidcController::class, 'logout']
    )->name('laracloak.logout');
});

Route::post(
    '/auth/backchannel-logout',
    [OidcController::class, 'backchannel'],
)->name('laracloak.backchannel');
