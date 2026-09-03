<?php

namespace Snairbef\Laracloak\Models;

use ArrayAccess;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Support\Arrayable;
use JsonSerializable;

final class User implements Authenticatable, JsonSerializable, Arrayable, ArrayAccess
{
    public function __construct(
        private array $attributes,
    ) {}

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
        return $this->getAttribute(
            $this->getAuthIdentifierName(),
        );
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
        return $this->getAttribute(
            $this->getAuthPasswordName(),
        );
    }

    /**
     * Get the remember token.
     */
    public function getRememberToken(): ?string
    {
        $token = $this->getAttribute(
            $this->getRememberTokenName(),
        );

        return is_string($token) ? $token : null;
    }

    /**
     * Set the remember token.
     */
    public function setRememberToken($value): void
    {
        $this->setAttribute(
            $this->getRememberTokenName(),
            $value,
        );
    }

    /**
     * Get the remember token name.
     */
    public function getRememberTokenName(): string
    {
        return 'remember_token';
    }

    /**
     * Get an attribute.
     */
    public function getAttribute(string $key): mixed
    {
        return $this->attributes[$key] ?? null;
    }

    /**
     * Set an attribute.
     */
    public function setAttribute(string $key, mixed $value): static
    {
        $this->attributes[$key] = $value;

        return $this;
    }

    /**
     * Get all attributes.
     */
    public function getAttributes(): array
    {
        return $this->attributes;
    }

    /**
     * Convert the user to an array.
     */
    public function toArray(): array
    {
        return $this->attributes;
    }

    /**
     * Convert the user to JSON data.
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * Get an attribute dynamically.
     */
    public function __get(string $key): mixed
    {
        return $this->getAttribute($key);
    }

    /**
     * Set an attribute dynamically.
     */
    public function __set(string $key, mixed $value): void
    {
        $this->setAttribute($key, $value);
    }

    /**
     * Check whether an attribute exists.
     */
    public function __isset(string $key): bool
    {
        return array_key_exists($key, $this->attributes);
    }

    /**
     * Get selected attributes.
     */
    public function only(array|string $keys): array
    {
        $keys = is_array($keys) ? $keys : [$keys];

        return array_intersect_key(
            $this->attributes,
            array_flip($keys),
        );
    }

    /**
     * Get all except selected attributes.
     */
    public function except(array|string $keys): array
    {
        $keys = is_array($keys) ? $keys : [$keys];

        return array_diff_key(
            $this->attributes,
            array_flip($keys),
        );
    }

    /**
     * Check whether an offset exists.
     */
    public function offsetExists(mixed $offset): bool
    {
        return array_key_exists(
            $offset,
            $this->attributes,
        );
    }

    /**
     * Get an offset value.
     */
    public function offsetGet(mixed $offset): mixed
    {
        return $this->getAttribute($offset);
    }

    /**
     * Set an offset value.
     */
    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->setAttribute($offset, $value);
    }

    /**
     * Remove an offset value.
     */
    public function offsetUnset(mixed $offset): void
    {
        unset($this->attributes[$offset]);
    }
}
