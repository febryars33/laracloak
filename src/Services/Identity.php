<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Services;

use Illuminate\Session\Store;
use Snairbef\Laracloak\Contracts\Identity as Contract;
use Snairbef\Laracloak\Contracts\Token;
use Snairbef\Laracloak\Contracts\Userinfo;
use Snairbef\Laracloak\Exceptions\OidcException;

final class Identity implements Contract
{
    public function __construct(
        private readonly Store $session,
        private readonly Userinfo $userinfo,
        private readonly Token $token,
    ) {}

    public function get(): ?array
    {
        $user = $this->current();

        if ($user === null) {
            return null;
        }

        if (! $this->stale()) {
            return $user;
        }

        return $this->sync($user);
    }

    public function sync(?array $current = null): ?array
    {
        $access = $this->token->access();

        if ($access === null) {
            return null;
        }

        $profile = $this->userinfo->get($access);

        $this->verify(
            $current ?? $this->current(),
            $profile,
        );

        $this->store($profile);

        return $profile;
    }

    public function current(): ?array
    {
        return $this->user();
    }

    public function clear(): void
    {
        $this->session->forget([
            $this->key('user'),
            $this->key('identity_at'),
        ]);
    }

    private function stale(): bool
    {
        $at = $this->session->get(
            $this->key('identity_at'),
        );

        if (! is_numeric($at)) {
            return true;
        }

        return now()->timestamp - (int) $at
            >= $this->ttl();
    }

    private function verify(
        ?array $current,
        array $profile,
    ): void {
        $expected = $current['sub'] ?? null;
        $actual = $profile['sub'] ?? null;

        if (
            ! is_string($expected)
            || ! is_string($actual)
            || $expected === ''
            || $actual === ''
            || ! hash_equals($expected, $actual)
        ) {
            throw OidcException::authentication(
                'OIDC subject mismatch.',
            );
        }
    }

    private function store(array $profile): void
    {
        $this->session->put(
            $this->key('user'),
            $profile,
        );

        $this->session->put(
            $this->key('identity_at'),
            now()->timestamp,
        );

        $this->session->save();
    }

    private function user(): ?array
    {
        $user = $this->session->get(
            $this->key('user'),
        );

        return is_array($user)
            ? $user
            : null;
    }

    private function ttl(): int
    {
        return max(
            1,
            (int) config(
                'laracloak.identity.ttl',
                30,
            ),
        );
    }

    private function key(string $name): string
    {
        $key = config(
            "laracloak.session.{$name}",
        );

        if (
            ! is_string($key)
            || trim($key) === ''
        ) {
            throw OidcException::configuration(
                "Laracloak session key [{$name}] is missing.",
            );
        }

        return trim($key);
    }
}
