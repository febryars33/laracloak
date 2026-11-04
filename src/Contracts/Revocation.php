<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Contracts;

interface Revocation
{
    public function revoke(string $id): void;

    public function revoked(string $id): bool;

    public function clear(string $id): void;
}
