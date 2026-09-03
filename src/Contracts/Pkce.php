<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Contracts;

interface Pkce
{
    public function generate(): string;

    public function challenge(string $verifier): string;
}
