<?php

namespace Snairbef\Laracloak\Contracts;

interface Oidc
{
    public function login(): string;

    public function token(string $code): array;

    public function refresh(array $token): array;

    public function user(array $token): array;

    public function logout(array $token): string;
}
