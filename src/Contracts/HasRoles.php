<?php

namespace Snairbef\Laracloak\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

interface HasRoles extends Authenticatable
{
    /**
     * Get the user's roles.
     *
     * @return array<int, string>
     */
    public function roles(): array;
}
