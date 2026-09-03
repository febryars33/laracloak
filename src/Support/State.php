<?php

namespace Snairbef\Laracloak\Support;

final class State
{
    public function generate(): string
    {
        return bin2hex(
            random_bytes(32),
        );
    }
}
