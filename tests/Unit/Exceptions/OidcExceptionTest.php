<?php

use Snairbef\Laracloak\Exceptions\OidcException;

it('creates configuration exceptions', function () {
    $exception = OidcException::configuration(
        'Configuration failed.',
    );

    expect($exception)
        ->toBeInstanceOf(OidcException::class)
        ->and($exception->getMessage())
        ->toBe('Configuration failed.')
        ->and($exception->status())
        ->toBeNull();
});

it('creates authentication exceptions', function () {
    $exception = OidcException::authentication(
        'Authentication failed.',
    );

    expect($exception->getMessage())
        ->toBe('Authentication failed.')
        ->and($exception->status())
        ->toBeNull();
});

it('creates HTTP exceptions with status', function () {
    $response = response()->json([], 401);

    $exception = OidcException::http($response);

    expect($exception->status())
        ->toBe(401)
        ->and($exception->getMessage())
        ->toBe('OIDC provider returned HTTP 401.');
});

it('preserves previous exceptions', function () {
    $previous = new RuntimeException('Previous.');

    $exception = OidcException::authentication(
        'Authentication failed.',
        $previous,
    );

    expect($exception->getPrevious())
        ->toBe($previous);
});
