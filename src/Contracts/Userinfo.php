<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Contracts;

interface Userinfo
{
    public function get(string $access): array;
}
