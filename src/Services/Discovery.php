<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Services;

use Illuminate\Support\Facades\Cache;
use Snairbef\Laracloak\Contracts\Discovery as Contract;
use Snairbef\Laracloak\Exceptions\ConfigurationException;
use Snairbef\Laracloak\Http\Client;

final class Discovery implements Contract
{
    public function __construct(
        private readonly Client $client,
    ) {}

    public function get(?string $key = null): array|string
    {
        $document = Cache::remember(
            $this->key(),
            now()->addSeconds(
                (int) config(
                    'laracloak.cache.ttl',
                    3600,
                ),
            ),
            fn (): array => $this->fetch(),
        );

        if ($key === null) {
            return $document;
        }

        $value = $document[$key] ?? null;

        if (
            ! is_string($value)
            || trim($value) === ''
        ) {
            throw new ConfigurationException("OIDC discovery field [{$key}] is missing.");
        }

        return trim($value);
    }

    private function fetch(): array
    {
        $issuer = config('laracloak.issuer');

        if (
            ! is_string($issuer)
            || trim($issuer) === ''
        ) {
            throw new ConfigurationException('OIDC issuer is not configured.');
        }

        $issuer = rtrim(
            trim($issuer),
            '/',
        );

        if (! filter_var(
            $issuer,
            FILTER_VALIDATE_URL,
        )) {
            throw new ConfigurationException("Invalid OIDC issuer: {$issuer}");
        }

        $response = $this->client->get(
            $issuer.'/.well-known/openid-configuration',
        );

        $document = $response->json();

        if (! is_array($document)) {
            throw new ConfigurationException('Invalid OIDC discovery response');
        }

        return $document;
    }

    private function key(): string
    {
        return 'laracloak.discovery.'.sha1(
            (string) config('laracloak.issuer'),
        );
    }
}
