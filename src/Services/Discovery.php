<?php

namespace Snairbef\Laracloak\Services;

use Illuminate\Support\Facades\Cache;
use Snairbef\Laracloak\Exceptions\OidcException;
use Snairbef\Laracloak\Http\Client;

final class Discovery
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
            fn(): array => $this->fetch(),
        );

        if ($key === null) {
            return $document;
        }

        $value = $document[$key] ?? null;

        if (
            ! is_string($value)
            || trim($value) === ''
        ) {
            throw OidcException::configuration(
                "OIDC discovery field [{$key}] is missing.",
            );
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
            throw OidcException::configuration(
                'OIDC issuer is not configured.',
            );
        }

        $issuer = rtrim(
            trim($issuer),
            '/',
        );

        if (! filter_var(
            $issuer,
            FILTER_VALIDATE_URL,
        )) {
            throw OidcException::configuration(
                "Invalid OIDC issuer: {$issuer}",
            );
        }

        $response = $this->client->get(
            $issuer . '/.well-known/openid-configuration',
        );

        $document = $response->json();

        if (! is_array($document)) {
            throw OidcException::configuration(
                'Invalid OIDC discovery response.',
            );
        }

        return $document;
    }

    private function key(): string
    {
        return 'laracloak.discovery.' . sha1(
            (string) config('laracloak.issuer'),
        );
    }
}
