<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

interface UserResolver
{
    public function resolve(array $attributes): ?Authenticatable;
}
