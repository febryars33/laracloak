<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Auth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Session\Store;
use Snairbef\Laracloak\Contracts\Identity;
use Snairbef\Laracloak\Contracts\Revocation;
use Snairbef\Laracloak\Contracts\UserResolver;

final class Guard implements StatefulGuard
{
    private ?Authenticatable $user = null;

    private bool $checked = false;

    public function __construct(
        private readonly string $name,
        private readonly Identity $identity,
        private Request $request,
        private readonly Store $session,
        private UserProvider $provider,
        private readonly Revocation $revocation,
        private readonly UserResolver $resolver,
    ) {}

    public function check(): bool
    {
        return $this->user() !== null;
    }

    public function guest(): bool
    {
        return ! $this->check();
    }

    public function user(): ?Authenticatable
    {
        if ($this->checked) {
            return $this->user;
        }

        $this->checked = true;

        $identity = $this->identity->current();

        if ($identity === null) {
            return null;
        }

        $subject = $this->subject($identity);

        if ($subject === null) {
            return $this->clear();
        }

        if ($this->revocation->revoked($subject)) {
            return $this->clear();
        }

        $attributes = $this->identity->get();

        if ($attributes === null) {
            return $this->clear();
        }

        $subject = $this->subject($attributes);

        if ($subject === null) {
            return $this->clear();
        }

        if ($this->revocation->revoked($subject)) {
            return $this->clear();
        }

        return $this->user = $this->resolver->resolve(
            $attributes,
        );
    }

    public function id(): mixed
    {
        return $this->user()?->getAuthIdentifier();
    }

    public function validate(array $credentials = []): bool
    {
        return $this->user() !== null;
    }

    public function hasUser(): bool
    {
        return $this->user !== null;
    }

    public function setUser(
        Authenticatable $user,
    ): static {
        $this->user = $user;
        $this->checked = true;

        return $this;
    }

    public function login(
        Authenticatable $user,
        $remember = false,
    ): void {
        $this->setUser($user);
    }

    public function attempt(
        array $credentials = [],
        $remember = false,
    ): bool {
        return $this->check();
    }

    public function loginUsingId(
        $id,
        $remember = false,
    ): Authenticatable|false {
        $user = $this->provider->retrieveById($id);

        if ($user === null) {
            return false;
        }

        $this->login($user, $remember);

        return $user;
    }

    public function once(array $credentials = []): bool
    {
        return $this->validate($credentials);
    }

    public function onceUsingId($id): Authenticatable|false
    {
        return $this->loginUsingId($id) !== false;
    }

    public function viaRemember(): bool
    {
        return false;
    }

    public function logout(): void
    {
        $this->clear();
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function setRequest(
        Request $request,
    ): static {
        $this->request = $request;

        return $this;
    }

    private function subject(array $attributes): ?string
    {
        $subject = $attributes['sub'] ?? null;

        return is_string($subject) && $subject !== ''
            ? $subject
            : null;
    }

    private function clear(): null
    {
        $this->identity->clear();

        $this->session->forget([
            config('laracloak.session.flow'),
            config('laracloak.session.token'),
        ]);

        $this->user = null;

        return null;
    }

    public function oidc(): bool
    {
        return true;
    }
}
