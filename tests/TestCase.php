<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Tests;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as Orchestra;
use Snairbef\Laracloak\LaracloakServiceProvider;

class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();

        Factory::guessFactoryNamesUsing(
            fn(string $modelName): string =>
            'Snairbef\\Laracloak\\Database\\Factories\\'
                . class_basename($modelName)
                . 'Factory',
        );

        $this->database();
    }

    protected function getPackageProviders($app): array
    {
        return [
            LaracloakServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app): void
    {
        config()->set(
            'app.key',
            'base64:' . base64_encode(
                str_repeat('x', 32),
            ),
        );

        config()->set(
            'database.default',
            'testing',
        );

        config()->set(
            'laracloak.issuer',
            'http://localhost:8000',
        );

        config()->set(
            'laracloak.client.id',
            'test-client',
        );

        config()->set(
            'laracloak.client.secret',
            'test-secret',
        );

        config()->set(
            'laracloak.redirect.login',
            'http://localhost:8001/auth/callback',
        );

        config()->set(
            'laracloak.post_logout_redirect_uri',
            'http://localhost:8001/',
        );

        config()->set(
            'auth.guards.laracloak',
            [
                'driver' => 'laracloak',
                'provider' => 'laracloak',
            ],
        );

        config()->set(
            'auth.providers.laracloak',
            [
                'driver' => 'laracloak',
            ],
        );
    }

    private function database(): void
    {
        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('sub')->unique();
            $table->string('name')->nullable();
            $table->string('email')->nullable();
            $table->string('password')->nullable();
            $table->rememberToken();
            $table->timestamps();
        });
    }
}
