<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Contracts;

interface Revocation
{
    public function revoke(string $subject): void;

    public function revoked(string $subject): bool;

    public function clear(string $subject): void;
}
