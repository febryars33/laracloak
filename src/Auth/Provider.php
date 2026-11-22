<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Auth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Snairbef\Laracloak\Contracts\Identity;
use Snairbef\Laracloak\Contracts\UserResolver;

final class Provider implements UserProvider
{
    public function __construct(
        private readonly Identity $identity,
        private readonly UserResolver $resolver,
    ) {}

    public function retrieveById(
        $identifier,
    ): ?Authenticatable {
        $attributes = $this->identity->get();

        if ($attributes === null) {
            return null;
        }

        $user = $this->resolver->resolve($attributes);

        if (
            $user === null
            || (string) $user->getAuthIdentifier() !== (string) $identifier
        ) {
            return null;
        }

        return $user;
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
