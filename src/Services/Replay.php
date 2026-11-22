<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Services;

use Closure;
use Illuminate\Support\Facades\Cache;
use Snairbef\Laracloak\Contracts\Replay as Contract;
use Snairbef\Laracloak\Exceptions\ConfigurationException;

final class Replay implements Contract
{
    private const PREFIX = 'laracloak.logout-token.';

    public function once(
        string $id,
        int $expiresAt,
        Closure $callback,
    ): bool {
        return Cache::lock(
            $this->key($id).'.lock',
            max(1, (int) config('laracloak.lock.seconds', 20)),
        )->block(
            max(1, (int) config('laracloak.lock.block', 5)),
            function () use ($id, $expiresAt, $callback): bool {
                $key = $this->key($id);

                if (Cache::has($key)) {
                    return false;
                }

                $callback();

                Cache::put(
                    $key,
                    true,
                    now()->addSeconds(
                        max(
                            1,
                            $expiresAt
                                + max(0, (int) config('laracloak.jwt.leeway', 5))
                                - now()->timestamp,
                        ),
                    ),
                );

                return true;
            },
        );
    }

    private function key(string $id): string
    {
        $issuer = config('laracloak.issuer');
        $client = config('laracloak.client.id');

        if (
            ! is_string($issuer)
            || trim($issuer) === ''
            || ! is_string($client)
            || trim($client) === ''
        ) {
            throw new ConfigurationException('OIDC issuer and client ID must be configured for logout token replay protection.');
        }

        return self::PREFIX.hash(
            'sha256',
            trim($issuer)."\0".trim($client)."\0".$id,
        );
    }
}
