<?php

namespace Snairbef\Laracloak\Services;

use Firebase\JWT\JWK as FirebaseJWK;
use Firebase\JWT\JWT as FirebaseJWT;
use Illuminate\Support\Facades\Cache;
use Snairbef\Laracloak\Exceptions\OidcException;
use Snairbef\Laracloak\Http\Client;

final class Jwt
{
    private const EVENT =
        'http://schemas.openid.net/event/backchannel-logout';

    private const CACHE = 'laracloak.jwks.';

    public function __construct(
        private readonly Discovery $discovery,
        private readonly Client $client,
    ) {}

    public function validate(string $token): object
    {
        try {
            return $this->decode($token);
        } catch (\Throwable $e) {
            throw OidcException::authentication(
                'Invalid OIDC ID token.',
                $e,
            );
        }
    }

    public function logout(string $token): array
    {
        if (trim($token) === '') {
            throw OidcException::authentication(
                'OIDC logout token is missing.',
            );
        }

        try {
            $claims = (array) $this->decode($token);
        } catch (\Throwable $e) {
            throw OidcException::authentication(
                'Invalid OIDC logout token.',
                $e,
            );
        }

        $this->event($claims);
        $this->issuer($claims);
        $this->audience($claims);
        $this->subject($claims);

        return $claims;
    }

    private function decode(string $token): object
    {
        $kid = $this->kid($token);

        $jwks = $this->keys();

        if (
            $kid !== null
            && ! $this->contains($jwks, $kid)
        ) {
            $jwks = $this->keys(true);
        }

        return FirebaseJWT::decode(
            $token,
            FirebaseJWK::parseKeySet($jwks),
        );
    }

    private function keys(bool $refresh = false): array
    {
        $key = $this->key();

        if ($refresh) {
            Cache::forget($key);
        }

        $jwks = Cache::remember(
            $key,
            now()->addSeconds(
                max(
                    60,
                    (int) config(
                        'laracloak.cache.ttl',
                        3600,
                    ),
                ),
            ),
            fn (): array => $this->fetch(),
        );

        if (! is_array($jwks)) {
            throw OidcException::authentication(
                'Invalid OIDC JWKS response.',
            );
        }

        return $jwks;
    }

    private function fetch(): array
    {
        $jwks = $this->client
            ->get(
                $this->discovery->get('jwks_uri'),
            )
            ->json();

        if (! is_array($jwks)) {
            throw OidcException::authentication(
                'Invalid OIDC JWKS response.',
            );
        }

        try {
            FirebaseJWK::parseKeySet($jwks);
        } catch (\Throwable $e) {
            throw OidcException::authentication(
                'Invalid OIDC JWKS.',
                $e,
            );
        }

        return $jwks;
    }

    private function kid(string $token): ?string
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            return null;
        }

        try {
            $header = json_decode(
                FirebaseJWT::urlsafeB64Decode($parts[0]),
                true,
                flags: JSON_THROW_ON_ERROR,
            );
        } catch (\Throwable) {
            return null;
        }

        $kid = $header['kid'] ?? null;

        return is_string($kid) && trim($kid) !== ''
            ? trim($kid)
            : null;
    }

    private function contains(
        array $jwks,
        string $kid,
    ): bool {
        $keys = $jwks['keys'] ?? null;

        if (! is_array($keys)) {
            return false;
        }

        foreach ($keys as $key) {
            if (
                is_array($key)
                && isset($key['kid'])
                && is_string($key['kid'])
                && hash_equals($key['kid'], $kid)
            ) {
                return true;
            }
        }

        return false;
    }

    private function event(array $claims): void
    {
        $events = $claims['events'] ?? null;

        if (! is_object($events) && ! is_array($events)) {
            throw OidcException::authentication(
                'Invalid OIDC logout event.',
            );
        }

        $events = (array) $events;

        if (! array_key_exists(self::EVENT, $events)) {
            throw OidcException::authentication(
                'Invalid OIDC logout event.',
            );
        }
    }

    private function issuer(array $claims): void
    {
        $actual = $claims['iss'] ?? null;

        if (! is_string($actual) || $actual === '') {
            throw OidcException::authentication(
                'OIDC logout issuer is missing.',
            );
        }

        $expected = $this->discovery->get('issuer');

        if (! hash_equals($expected, $actual)) {
            throw OidcException::authentication(
                'Invalid OIDC logout issuer.',
            );
        }
    }

    private function audience(array $claims): void
    {
        $audience = $claims['aud'] ?? null;

        $audiences = is_array($audience)
            ? $audience
            : [$audience];

        $client = (string) config(
            'laracloak.client.id',
        );

        foreach ($audiences as $value) {
            if (
                is_string($value)
                && hash_equals($client, $value)
            ) {
                return;
            }
        }

        throw OidcException::authentication(
            'Invalid OIDC logout audience.',
        );
    }

    private function subject(array $claims): void
    {
        $subject = $claims['sub'] ?? null;

        if (! is_string($subject) || $subject === '') {
            throw OidcException::authentication(
                'OIDC logout subject is missing.',
            );
        }
    }

    private function key(): string
    {
        return self::CACHE.sha1(
            (string) config('laracloak.issuer'),
        );
    }
}
