<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Contracts;

interface Discovery
{
    public function get(?string $key = null): array|string;
}
