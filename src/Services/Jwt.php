<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Services;

use Firebase\JWT\JWK as FirebaseJWK;
use Firebase\JWT\JWT as FirebaseJWT;
use Firebase\JWT\Key;
use Illuminate\Support\Facades\Cache;
use Snairbef\Laracloak\Contracts\Jwt as Contract;
use Snairbef\Laracloak\Exceptions\AuthenticationException;
use Snairbef\Laracloak\Exceptions\ConfigurationException;
use Snairbef\Laracloak\Http\Client;

final class Jwt implements Contract
{
    private const EVENT =
        'http://schemas.openid.net/event/backchannel-logout';

    private const CACHE = 'laracloak.jwks.';

    private const ALGORITHMS = [
        'RS256',
        'RS384',
        'RS512',
        'PS256',
        'ES256',
        'ES256K',
        'ES384',
        'EdDSA',
    ];

    public function __construct(
        private readonly Discovery $discovery,
        private readonly Client $client,
    ) {}

    public function validate(string $token): object
    {
        $claims = (array) $this->decode($token, 'ID token');

        $this->issuer($claims, 'ID token');
        $this->audience($claims, 'ID token');
        $this->subject($claims, 'ID token');
        $this->timestamps($claims, 'ID token');

        return (object) $claims;
    }

    public function logout(string $token): array
    {
        if (trim($token) === '') {
            throw new AuthenticationException('OIDC logout token is missing.');
        }

        $claims = (array) $this->decode($token, 'logout token');

        $this->event($claims);
        $this->issuer($claims, 'logout token');
        $this->audience($claims, 'logout token');
        $this->subject($claims, 'logout token');
        $this->timestamps($claims, 'logout token');

        if (array_key_exists('nonce', $claims)) {
            throw new AuthenticationException('OIDC logout token must not contain a nonce.');
        }

        $jti = $claims['jti'] ?? null;

        if (! is_string($jti) || trim($jti) === '') {
            throw new AuthenticationException('OIDC logout token identifier is missing.');
        }

        return $claims;
    }

    private function decode(
        string $token,
        string $type,
    ): object {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new AuthenticationException("Invalid OIDC {$type}.");
        }

        try {
            $header = json_decode(
                FirebaseJWT::urlsafeB64Decode($parts[0]),
                true,
                flags: JSON_THROW_ON_ERROR,
            );
        } catch (\Throwable $e) {
            throw new AuthenticationException(
                message: "Invalid OIDC {$type}.",
                previous: $e,
            );
        }

        if (! is_array($header)) {
            throw new AuthenticationException("Invalid OIDC {$type}.");
        }

        $algorithm = $header['alg'] ?? null;

        if (
            ! is_string($algorithm)
            || ! in_array($algorithm, $this->algorithms(), true)
        ) {
            throw new AuthenticationException("Invalid OIDC {$type} algorithm.");
        }

        $kid = $header['kid'] ?? null;

        if (
            $kid !== null
            && (! is_string($kid) || trim($kid) === '')
        ) {
            throw new AuthenticationException("Invalid OIDC {$type} key identifier.");
        }

        $jwks = $this->keys();
        $keys = $this->parseKeys($jwks, $algorithm);

        if ($kid !== null && ! isset($keys[$kid])) {
            $keys = $this->parseKeys(
                $this->keys(true),
                $algorithm,
            );
        }

        $key = $kid !== null
            ? ($keys[$kid] ?? null)
            : (count($keys) === 1 ? reset($keys) : null);

        if (! $key instanceof Key) {
            throw new AuthenticationException("Invalid OIDC {$type} signing key.");
        }

        $leeway = max(0, (int) config('laracloak.jwt.leeway', 5));
        $previous = FirebaseJWT::$leeway;

        FirebaseJWT::$leeway = $leeway;

        try {
            return FirebaseJWT::decode(
                $token,
                $key,
            );
        } catch (\Throwable $e) {
            throw new AuthenticationException(
                message: "Invalid OIDC {$type}.",
                previous: $e,
            );
        } finally {
            FirebaseJWT::$leeway = $previous;
        }
    }

    /**
     * @return list<string>
     */
    private function algorithms(): array
    {
        $algorithms = config(
            'laracloak.jwt.algorithms',
            ['RS256'],
        );

        if (
            ! is_array($algorithms)
            || $algorithms === []
        ) {
            throw new ConfigurationException('OIDC signing algorithms must be a non-empty array.');
        }

        foreach ($algorithms as $algorithm) {
            if (
                ! is_string($algorithm)
                || ! in_array($algorithm, self::ALGORITHMS, true)
            ) {
                throw new ConfigurationException('OIDC signing algorithms contain an unsupported value.');
            }
        }

        return array_values(array_unique($algorithms));
    }

    /**
     * @return array<string, Key>
     */
    private function parseKeys(
        array $jwks,
        string $algorithm,
    ): array {
        $candidates = $jwks['keys'] ?? null;

        if (! is_array($candidates) || $candidates === []) {
            throw new AuthenticationException('Invalid OIDC JWKS.');
        }

        $keys = [];

        foreach ($candidates as $index => $candidate) {
            if (
                ! is_array($candidate)
                || (isset($candidate['use']) && $candidate['use'] !== 'sig')
                || (
                    isset($candidate['key_ops'])
                    && (
                        ! is_array($candidate['key_ops'])
                        || ! in_array('verify', $candidate['key_ops'], true)
                    )
                )
                || (
                    isset($candidate['alg'])
                    && $candidate['alg'] !== $algorithm
                )
            ) {
                continue;
            }

            try {
                $key = FirebaseJWK::parseKey(
                    $candidate,
                    $algorithm,
                );
            } catch (\Throwable $e) {
                throw new AuthenticationException(
                    message: 'Invalid OIDC JWKS.',
                    previous: $e,
                );
            }

            if (! $key instanceof Key || $key->getAlgorithm() !== $algorithm) {
                continue;
            }

            $id = $candidate['kid'] ?? '#'.$index;

            if (! is_string($id) && ! is_int($id)) {
                throw new AuthenticationException('Invalid OIDC JWKS key identifier.');
            }

            $id = (string) $id;

            if (array_key_exists($id, $keys)) {
                throw new AuthenticationException('OIDC JWKS contains duplicate key identifiers.');
            }

            $keys[$id] = $key;
        }

        if ($keys === []) {
            throw new AuthenticationException('OIDC JWKS has no compatible signing keys.');
        }

        return $keys;
    }

    private function keys(bool $refresh = false): array
    {
        $key = $this->key();

        if ($refresh) {
            Cache::forget($key);
        }

        return Cache::remember(
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
    }

    private function fetch(): array
    {
        $jwks = $this->client
            ->get(
                $this->discovery->get('jwks_uri'),
            )
            ->json();

        if (
            ! is_array($jwks)
            || ! is_array($jwks['keys'] ?? null)
            || $jwks['keys'] === []
        ) {
            throw new AuthenticationException('Invalid OIDC JWKS.');
        }

        return $jwks;
    }

    private function event(array $claims): void
    {
        $events = $claims['events'] ?? null;

        if (! is_object($events)) {
            throw new AuthenticationException('Invalid OIDC logout event.');
        }

        $events = get_object_vars($events);

        if (
            ! array_key_exists(self::EVENT, $events)
            || ! is_object($events[self::EVENT])
        ) {
            throw new AuthenticationException('Invalid OIDC logout event.');
        }
    }

    private function issuer(
        array $claims,
        string $type,
    ): void {
        $actual = $claims['iss'] ?? null;

        if (! is_string($actual) || $actual === '') {
            $message = $type === 'logout token'
                ? 'OIDC logout issuer is missing.'
                : 'OIDC ID token issuer is missing.';

            throw new AuthenticationException($message);
        }

        $expected = $this->discovery->get('issuer');

        if (! hash_equals($expected, $actual)) {
            $message = $type === 'logout token'
                ? 'Invalid OIDC logout issuer.'
                : 'Invalid OIDC ID token issuer.';

            throw new AuthenticationException($message);
        }
    }

    private function audience(
        array $claims,
        string $type,
    ): void {
        $audience = $claims['aud'] ?? null;

        if (
            ! is_string($audience)
            && ! is_array($audience)
        ) {
            $this->invalidAudience($type);
        }

        $audiences = is_array($audience)
            ? $audience
            : [$audience];

        if ($audiences === [] || ! array_is_list($audiences)) {
            $this->invalidAudience($type);
        }

        foreach ($audiences as $value) {
            if (! is_string($value) || $value === '') {
                $this->invalidAudience($type);
            }
        }

        $client = config('laracloak.client.id');

        if (
            ! is_string($client)
            || trim($client) === ''
        ) {
            throw new ConfigurationException('Laracloak client ID is not configured.');
        }

        if (! in_array($client, $audiences, true)) {
            $this->invalidAudience($type);
        }

        if ($type === 'ID token' && count($audiences) > 1) {
            $authorized = $claims['azp'] ?? null;

            if (! is_string($authorized) || ! hash_equals($client, $authorized)) {
                throw new AuthenticationException('Invalid OIDC ID token authorized party.');
            }
        }

        if (array_key_exists('azp', $claims)) {
            $authorized = $claims['azp'];

            if (! is_string($authorized) || ! hash_equals($client, $authorized)) {
                $message = $type === 'logout token'
                    ? 'Invalid OIDC logout authorized party.'
                    : 'Invalid OIDC ID token authorized party.';

                throw new AuthenticationException($message);
            }
        }
    }

    private function invalidAudience(string $type): never
    {
        $message = $type === 'logout token'
            ? 'Invalid OIDC logout audience.'
            : 'Invalid OIDC ID token audience.';

        throw new AuthenticationException($message);
    }

    private function subject(
        array $claims,
        string $type,
    ): void {
        $subject = $claims['sub'] ?? null;
        $sid = $claims['sid'] ?? null;

        $hasSub = is_string($subject)
            && $subject !== ''
            && strlen($subject) <= 255
            && preg_match('/\A[\x00-\x7F]+\z/D', $subject) === 1;
        $hasSid = is_string($sid) && trim($sid) !== '';

        if (
            ($type === 'ID token' && ! $hasSub)
            || ($type === 'logout token' && ! $hasSub && ! $hasSid)
            || ($subject !== null && ! $hasSub)
            || ($sid !== null && ! $hasSid)
        ) {
            $message = $type === 'ID token'
                ? 'OIDC ID token subject is missing.'
                : 'OIDC logout subject is missing.';

            throw new AuthenticationException($message);
        }
    }

    private function timestamps(
        array $claims,
        string $type,
    ): void {
        foreach (['iat', 'exp'] as $name) {
            $value = $claims[$name] ?? null;

            if (
                (! is_int($value) && ! is_float($value))
                || ! is_finite((float) $value)
            ) {
                throw new AuthenticationException("OIDC {$type} {$name} claim is missing or invalid.");
            }
        }

        $leeway = max(0, (int) config('laracloak.jwt.leeway', 5));

        if ((float) $claims['iat'] > now()->timestamp + $leeway) {
            throw new AuthenticationException("OIDC {$type} issued-at time is in the future.");
        }
    }

    private function key(): string
    {
        return self::CACHE.sha1(
            (string) config('laracloak.issuer'),
        );
    }
}
