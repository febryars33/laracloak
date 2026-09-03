<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Contracts;

interface Token
{
    public function exchange(
        string $code,
        string $verifier,
    ): array;

    public function refresh(
        string $refresh,
    ): array;

    public function access(): ?string;
}
