<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Exceptions;

use RuntimeException;
use Throwable;

final class OidcException extends RuntimeException
{
    public function __construct(
        string $message,
        private readonly ?int $status = null,
        ?Throwable $previous = null,
    ) {
        parent::__construct(
            $message,
            0,
            $previous,
        );
    }

    public static function configuration(
        string $message,
        ?Throwable $previous = null,
    ): self {
        return new self(
            $message,
            null,
            $previous,
        );
    }

    public static function authentication(
        string $message,
        ?Throwable $previous = null,
    ): self {
        return new self(
            $message,
            null,
            $previous,
        );
    }

    public static function http(
        object $response,
        ?Throwable $previous = null,
    ): self {
        $status = method_exists($response, 'status')
            ? $response->status()
            : null;

        $message = $status
            ? "OIDC provider returned HTTP {$status}."
            : 'OIDC provider returned an HTTP error.';

        return new self(
            $message,
            is_int($status) ? $status : null,
            $previous,
        );
    }

    public function status(): ?int
    {
        return $this->status;
    }
}
