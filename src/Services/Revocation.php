<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Services;

use Illuminate\Support\Facades\Cache;
use Snairbef\Laracloak\Contracts\Revocation as Contract;

final class Revocation implements Contract
{
    public function revoke(string $subject): void
    {
        Cache::put(
            $this->key($subject),
            now()->timestamp,
            now()->addDays(1),
        );
    }

    public function revoked(string $subject): bool
    {
        return Cache::has(
            $this->key($subject),
        );
    }

    public function clear(string $subject): void
    {
        Cache::forget(
            $this->key($subject),
        );
    }

    private function key(string $subject): string
    {
        return 'laracloak.logout.' . sha1($subject);
    }
}
