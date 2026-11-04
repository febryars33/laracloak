<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Models;

use ArrayAccess;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Foundation\Auth\User as AuthUser;
use JsonSerializable;

class User extends AuthUser implements Arrayable, ArrayAccess, Authenticatable, JsonSerializable
{
    /**
     * @var array<int, string>
     */
    protected $guarded = [];

    /**
     * Get the authentication identifier name.
     */
    public function getAuthIdentifierName(): string
    {
        return 'sub';
    }

    /**
     * Get the authentication identifier.
     */
    public function getAuthIdentifier(): mixed
    {
        return $this->getAttribute($this->getAuthIdentifierName());
    }

    /**
     * Get the authentication password name.
     */
    public function getAuthPasswordName(): string
    {
        return 'password';
    }

    /**
     * Get the authentication password.
     */
    public function getAuthPassword(): ?string
    {
        return $this->getAttribute($this->getAuthPasswordName());
    }

    /**
     * Get the remember token.
     */
    public function getRememberToken(): ?string
    {
        $token = $this->getAttribute($this->getRememberTokenName());

        return is_string($token) ? $token : null;
    }

    /**
     * Set the remember token.
     */
    public function setRememberToken($value): void
    {
        $this->setAttribute($this->getRememberTokenName(), $value);
    }

    /**
     * Get the remember token name.
     */
    public function getRememberTokenName(): string
    {
        return 'remember_token';
    }
}
