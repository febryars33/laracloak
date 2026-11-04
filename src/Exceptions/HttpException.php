<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Exceptions;

use Illuminate\Http\Client\Response;
use RuntimeException;
use Snairbef\Laracloak\Contracts\LaracloakException;
use Throwable;

final class HttpException extends RuntimeException implements LaracloakException
{
    private readonly int $statusCode;

    /**
     * HttpException constructor.
     */
    public function __construct(Response $response, ?Throwable $previous = null)
    {
        $this->statusCode = $response->status();

        $message = "OIDC provider returned HTTP status {$this->statusCode}.";

        parent::__construct($message, 0, $previous);
    }

    /**
     * Get the HTTP status code from the provider response.
     */
    public function getStatusCode(): int
    {
        return $this->statusCode;
    }

    /**
     * Determine whether the HTTP error indicates an invalid or revoked token.
     */
    public function unauthenticated(): bool
    {
        return $this->statusCode === 401;
    }
}
