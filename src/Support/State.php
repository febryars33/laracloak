<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Support;

use Snairbef\Laracloak\Contracts\State as Contract;

final class State implements Contract
{
    public function generate(): string
    {
        return bin2hex(
            random_bytes(32),
        );
    }
}
