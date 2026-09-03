<?php

namespace Snairbef\Laracloak\Auth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Snairbef\Laracloak\Services\Identity;

final class Provider implements UserProvider
{
    public function __construct(
        private readonly Identity $identity,
    ) {}

    public function retrieveById(
        $identifier,
    ): ?Authenticatable {
        $attributes = $this->identity->get();

        if ($attributes === null) {
            return null;
        }

        $subject = $attributes['sub'] ?? null;

        if (
            ! is_string($subject)
            || $subject !== (string) $identifier
        ) {
            return null;
        }

        return new User(
            $attributes,
        );
    }

    public function retrieveByToken(
        $identifier,
        $token,
    ): ?Authenticatable {
        return null;
    }

    public function updateRememberToken(
        Authenticatable $user,
        $token,
    ): void {}

    public function retrieveByCredentials(
        array $credentials,
    ): ?Authenticatable {
        return null;
    }

    public function validateCredentials(
        Authenticatable $user,
        array $credentials,
    ): bool {
        return false;
    }

    public function rehashPasswordIfRequired(
        Authenticatable $user,
        array $credentials,
        bool $force = false,
    ): void {}
}
