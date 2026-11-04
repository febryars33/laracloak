<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Exceptions;

use Illuminate\Http\Client\Response;
use RuntimeException;
use Snairbef\Laracloak\Contracts\LaracloakException;
use Throwable;

/**
 * @package Snairbef\Laracloak\Exceptions
 */
final class HttpException extends RuntimeException implements LaracloakException
{
    /**
     * @var int
     */
    private readonly int $statusCode;

    /**
     * HttpException constructor.
     *
     * @param Response $response
     * @param Throwable|null $previous
     */
    public function __construct(Response $response, ?Throwable $previous = null)
    {
        $this->statusCode = $response->status();

        $message = "OIDC provider returned HTTP status {$this->statusCode}.";

        parent::__construct($message, 0, $previous);
    }

    /**
     * Get the HTTP status code from the provider response.
     *
     * @return int
     */
    public function getStatusCode(): int
    {
        return $this->statusCode;
    }
}
