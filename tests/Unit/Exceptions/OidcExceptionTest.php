<?php

use Illuminate\Support\Facades\Http;
use Snairbef\Laracloak\Exceptions\AuthenticationException;
use Snairbef\Laracloak\Exceptions\ConfigurationException;
use Snairbef\Laracloak\Exceptions\HttpException;

it('creates configuration exceptions', function () {
    $exception = new ConfigurationException('Configuration failed.');

    expect($exception)
        ->toBeInstanceOf(ConfigurationException::class)
        ->and($exception->getMessage())
        ->toBe('Configuration failed.');
});

it('creates authentication exceptions', function () {
    $exception = new AuthenticationException('Authentication failed.');

    expect($exception->getMessage())
        ->toBe('Authentication failed.');
});

it('creates HTTP exceptions with status', function () {
    Http::fake([
        '*' => Http::response([], 401),
    ]);

    $response = Http::get('https://example.com');

    $exception = new HttpException($response);

    expect($exception->getStatusCode())
        ->toBe(401)
        ->and($exception->getMessage())
        ->toBe('OIDC provider returned HTTP status 401.');
});

it('preserves previous exceptions', function () {
    $previous = new RuntimeException('Previous.');

    $exception = new AuthenticationException(message: 'Authentication failed.', previous: $previous);

    expect($exception->getPrevious())
        ->toBe($previous);
});
