<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Contracts;

interface Identity
{
    public function get(): ?array;

    public function current(): ?array;

    public function sync(?array $current = null): ?array;

    public function clear(): void;
}
