<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Contracts;

use Closure;

interface Replay
{
    public function once(
        string $id,
        int $expiresAt,
        Closure $callback,
    ): bool;
}
