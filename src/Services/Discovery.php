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
                $this->ttl(),
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
        $issuer = $this->issuer();

        $response = $this->client->get(
            $issuer.'/.well-known/openid-configuration',
        );

        $document = $response->json();

        if (
            ! is_array($document)
            || array_is_list($document)
        ) {
            throw new ConfigurationException('Invalid OIDC discovery response');
        }

        $actual = $document['issuer'] ?? null;

        if (
            ! is_string($actual)
            || $actual !== $issuer
        ) {
            throw new ConfigurationException('OIDC discovery issuer does not match the configured issuer.');
        }

        foreach (
            [
                'authorization_endpoint',
                'token_endpoint',
                'jwks_uri',
                'userinfo_endpoint',
            ] as $field
        ) {
            $this->endpoint($document, $field, true);
        }

        if (array_key_exists('end_session_endpoint', $document)) {
            $this->endpoint($document, 'end_session_endpoint', false);
        }

        return $document;
    }

    private function issuer(): string
    {
        $issuer = config('laracloak.issuer');

        if (
            ! is_string($issuer)
            || trim($issuer) === ''
        ) {
            throw new ConfigurationException('OIDC issuer is not configured.');
        }

        if (
            $issuer !== trim($issuer)
            || ! filter_var($issuer, FILTER_VALIDATE_URL)
        ) {
            throw new ConfigurationException("Invalid OIDC issuer: {$issuer}");
        }

        $scheme = parse_url($issuer, PHP_URL_SCHEME);
        $host = parse_url($issuer, PHP_URL_HOST);
        $query = parse_url($issuer, PHP_URL_QUERY);
        $fragment = parse_url($issuer, PHP_URL_FRAGMENT);

        if (
            ! is_string($scheme)
            || ! in_array($scheme, ['http', 'https'], true)
            || ! is_string($host)
            || $host === ''
            || $query !== null
            || $fragment !== null
        ) {
            throw new ConfigurationException("Invalid OIDC issuer: {$issuer}");
        }

        if (
            $scheme !== 'https'
            && ! in_array(
                strtolower($host),
                ['localhost', '127.0.0.1', '::1'],
                true,
            )
        ) {
            throw new ConfigurationException('OIDC issuer must use HTTPS except for loopback hosts.');
        }

        return $issuer;
    }

    private function key(): string
    {
        return 'laracloak.discovery.'.sha1(
            $this->issuer(),
        );
    }

    private function endpoint(
        array $document,
        string $field,
        bool $required,
    ): void {
        $value = $document[$field] ?? null;

        if (
            ! is_string($value)
            || trim($value) === ''
        ) {
            if ($required) {
                throw new ConfigurationException("OIDC discovery field [{$field}] is missing.");
            }

            return;
        }

        $value = trim($value);
        $scheme = parse_url($value, PHP_URL_SCHEME);
        $host = parse_url($value, PHP_URL_HOST);

        if (
            ! filter_var($value, FILTER_VALIDATE_URL)
            || ! is_string($scheme)
            || ! in_array($scheme, ['http', 'https'], true)
            || ! is_string($host)
            || $host === ''
        ) {
            throw new ConfigurationException("OIDC discovery field [{$field}] is not a valid URL.");
        }

        if (
            $scheme === 'http'
            && ! in_array(
                strtolower($host),
                ['localhost', '127.0.0.1', '::1'],
                true,
            )
        ) {
            throw new ConfigurationException("OIDC discovery field [{$field}] must use HTTPS.");
        }
    }

    private function ttl(): int
    {
        $ttl = (int) config(
            'laracloak.cache.ttl',
            3600,
        );

        return max(1, $ttl);
    }
}
