<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Support;

use Snairbef\Laracloak\Contracts\Pkce as Contract;

final class Pkce implements Contract
{
    public function generate(): string
    {
        return $this->encode(
            random_bytes(64),
        );
    }

    public function challenge(string $verifier): string
    {
        return $this->encode(
            hash(
                'sha256',
                $verifier,
                true,
            ),
        );
    }

    private function encode(string $value): string
    {
        return rtrim(
            strtr(
                base64_encode($value),
                '+/',
                '-_',
            ),
            '=',
        );
    }
}
