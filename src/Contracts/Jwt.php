<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Contracts;

interface Jwt
{
    public function validate(string $token): object;

    public function logout(string $token): array;
}
