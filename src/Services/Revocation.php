<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Services;

use Illuminate\Support\Facades\Cache;
use Snairbef\Laracloak\Contracts\Revocation as Contract;

final class Revocation implements Contract
{
    public function revoke(string $id): void
    {
        Cache::put(
            $this->key($id),
            now()->timestamp,
            now()->addDays(1),
        );
    }

    public function revoked(string $id): bool
    {
        return Cache::has(
            $this->key($id),
        );
    }

    public function clear(string $id): void
    {
        Cache::forget(
            $this->key($id),
        );
    }

    private function key(string $id): string
    {
        return 'laracloak.logout.'.sha1($id);
    }
}
