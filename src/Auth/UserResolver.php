<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Auth;

use App\Models\User;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use RuntimeException;
use Snairbef\Laracloak\Contracts\UserResolver as Contract;

final class UserResolver implements Contract
{
    public function resolve(array $attributes): ?Authenticatable
    {
        $subject = $attributes['sub'] ?? null;

        if (! is_string($subject) || $subject === '') {
            return null;
        }

        $model = $this->model();

        $user = $model::query()
            ->where('sub', $subject)
            ->first();

        if ($user !== null) {
            return $this->sync($user, $attributes);
        }

        if (! config('laracloak.user.provision', true)) {
            return null;
        }

        return $this->create($model, $attributes);
    }

    private function model(): string
    {
        $model = config(
            'laracloak.user.model',
            User::class,
        );

        if (
            ! is_string($model)
            || ! is_a($model, Authenticatable::class, true)
            || ! is_a($model, Model::class, true)
        ) {
            throw new RuntimeException(
                'Laracloak user model must extend an Eloquent Authenticatable model.',
            );
        }

        return $model;
    }

    private function sync(
        Model&Authenticatable $user,
        array $attributes,
    ): Model&Authenticatable {
        $data = $this->attributes($attributes);

        $user->forceFill($data);

        if ($user->isDirty()) {
            $user->save();
        }

        return $user;
    }

    private function create(
        string $model,
        array $attributes,
    ): Model&Authenticatable {
        $user = new $model;

        $user->forceFill(
            $this->attributes($attributes),
        );

        $user->save();

        return $user;
    }

    private function attributes(array $attributes): array
    {
        return array_filter([
            'sub' => $attributes['sub'] ?? null,
            'name' => $attributes['name'] ?? null,
            'email' => $attributes['email'] ?? null,
        ], static fn (mixed $value): bool => $value !== null);
    }
}
