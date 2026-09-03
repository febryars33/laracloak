<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Services;

use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Cache;
use Snairbef\Laracloak\Contracts\Token as Contract;
use Snairbef\Laracloak\Exceptions\OidcException;
use Snairbef\Laracloak\Http\Client;

final class Token implements Contract
{
    public function __construct(
        private readonly Client $client,
        private readonly Discovery $discovery,
        private readonly Store $session,
    ) {}

    public function exchange(
        string $code,
        string $verifier,
    ): array {
        return $this->send([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'client_id' => $this->id(),
            'redirect_uri' => $this->redirect(),
            'code_verifier' => $verifier,
        ]);
    }

    public function refresh(string $refresh): array
    {
        $tokens = $this->send([
            'grant_type' => 'refresh_token',
            'refresh_token' => $refresh,
            'client_id' => $this->id(),
        ]);

        $tokens['refresh_token'] ??= $refresh;

        return $tokens;
    }

    public function access(): ?string
    {
        $tokens = $this->tokens();

        if ($tokens === null) {
            return null;
        }

        $access = $this->value(
            $tokens['access_token'] ?? null,
        );

        if ($access === null) {
            throw OidcException::authentication(
                'OIDC access token is missing.',
            );
        }

        if (! $this->expired($tokens)) {
            return $access;
        }

        return $this->renew();
    }

    private function renew(): ?string
    {
        try {
            return Cache::lock(
                $this->lock(),
                $this->seconds(),
            )->block(
                $this->block(),
                function (): ?string {
                    /*
                     * Another request may have refreshed the token
                     * while this request was waiting for the lock.
                     */
                    $tokens = $this->tokens();

                    if ($tokens === null) {
                        return null;
                    }

                    $access = $this->value(
                        $tokens['access_token'] ?? null,
                    );

                    if (
                        $access !== null
                        && ! $this->expired($tokens)
                    ) {
                        return $access;
                    }

                    $refresh = $this->value(
                        $tokens['refresh_token'] ?? null,
                    );

                    if ($refresh === null) {
                        throw OidcException::authentication(
                            'OIDC refresh token is missing.',
                        );
                    }

                    $tokens = $this->refresh($refresh);

                    $access = $this->value(
                        $tokens['access_token'] ?? null,
                    );

                    if ($access === null) {
                        throw OidcException::authentication(
                            'OIDC refresh response does not contain an access token.',
                        );
                    }

                    $this->store($tokens);

                    return $access;
                },
            );
        } catch (LockTimeoutException $e) {
            throw OidcException::authentication(
                'Unable to refresh the OIDC access token.',
                $e,
            );
        }
    }

    private function expired(array $tokens): bool
    {
        $created = $tokens['created_at'] ?? null;
        $expires = $tokens['expires_in'] ?? null;

        if (
            ! is_numeric($created)
            || ! is_numeric($expires)
        ) {
            return true;
        }

        return now()->timestamp >= (
            (int) $created
            + (int) $expires
            - 30
        );
    }

    private function tokens(): ?array
    {
        $tokens = $this->session->get(
            config('laracloak.session.token'),
        );

        return is_array($tokens)
            ? $tokens
            : null;
    }

    private function store(array $tokens): void
    {
        $this->session->put(
            config('laracloak.session.token'),
            $tokens,
        );

        $this->session->save();
    }

    private function send(array $data): array
    {
        if (
            config('laracloak.authentication.method')
            === 'client_secret_post'
        ) {
            $data['client_secret'] = $this->secret();
        }

        $response = $this->client->post(
            $this->discovery->get('token_endpoint'),
            $data,
        );

        if ($response->failed()) {
            $body = $response->json();

            if (
                is_array($body)
                && ($body['error'] ?? null) === 'invalid_grant'
            ) {
                throw OidcException::authentication(
                    'OIDC refresh token is invalid or revoked.',
                );
            }

            throw OidcException::http($response);
        }

        $tokens = $response->json();

        if (! is_array($tokens)) {
            throw OidcException::authentication(
                'Invalid OIDC token response.',
            );
        }

        $tokens['created_at'] = now()->timestamp;

        return $tokens;
    }

    private function lock(): string
    {
        return 'laracloak.token.'.sha1(
            $this->id().'|'.$this->session->getId(),
        );
    }

    private function seconds(): int
    {
        return max(
            1,
            (int) config(
                'laracloak.lock.seconds',
                20,
            ),
        );
    }

    private function block(): int
    {
        return max(
            1,
            (int) config(
                'laracloak.lock.block',
                5,
            ),
        );
    }

    private function id(): string
    {
        return $this->valueOrFail(
            config('laracloak.client.id'),
            'laracloak.client.id',
        );
    }

    private function secret(): string
    {
        return $this->valueOrFail(
            config('laracloak.client.secret'),
            'laracloak.client.secret',
        );
    }

    private function redirect(): string
    {
        return $this->valueOrFail(
            config('laracloak.redirect.login'),
            'laracloak.redirect.login',
        );
    }

    private function value(
        mixed $value,
    ): ?string {
        if (
            ! is_string($value)
            || trim($value) === ''
        ) {
            return null;
        }

        return trim($value);
    }

    private function valueOrFail(
        mixed $value,
        string $key,
    ): string {
        $value = $this->value($value);

        if ($value === null) {
            throw OidcException::configuration(
                "Laracloak configuration [{$key}] is missing.",
            );
        }

        return $value;
    }
}
