<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Auth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Log;
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

        $sid = $this->sid();

        if ($this->revoked($subject, $sid)) {
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

        $sid = $this->sid();

        Log::info('Laracloak guard revocation check.', [
            'subject' => $subject,
            'sid' => $sid,
            'subject_revoked' => $this->revocation->revoked($subject),
            'legacy_revoked' => $this->revocation->revoked('legacy:'.$subject),
            'sid_revoked' => $sid !== null
                ? $this->revocation->revoked($sid)
                : null,
        ]);

        if ($this->revoked($subject, $sid)) {
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

    public function onceUsingId(
        $id,
    ): Authenticatable|false {
        return $this->loginUsingId($id);
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

    private function subject(array $attributes): ?string
    {
        $subject = $attributes['sub'] ?? null;

        return is_string($subject) && $subject !== ''
            ? $subject
            : null;
    }

    private function sid(): ?string
    {
        $sid = $this->session->get(
            (string) config('laracloak.session.sid'),
        );

        return is_string($sid) && trim($sid) !== ''
            ? trim($sid)
            : null;
    }

    private function revoked(
        string $subject,
        ?string $sid,
    ): bool {
        if ($sid !== null && $this->revocation->revoked($sid)) {
            return true;
        }

        if ($this->revocation->revoked($subject)) {
            return true;
        }

        return $sid === null && $this->revocation->revoked('legacy:'.$subject);
    }

    private function clear(): null
    {
        $this->identity->clear();

        $this->session->forget([
            config('laracloak.session.flow'),
            config('laracloak.session.token'),
            config('laracloak.session.sid'),
        ]);

        $this->user = null;

        return null;
    }

    public function oidc(): bool
    {
        return true;
    }
}
