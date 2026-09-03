<?php

namespace Snairbef\Laracloak;

use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use Snairbef\Laracloak\Auth\Guard;
use Snairbef\Laracloak\Auth\Provider;
use Snairbef\Laracloak\Auth\UserResolver;
use Snairbef\Laracloak\Http\Client;
use Snairbef\Laracloak\Services\Discovery;
use Snairbef\Laracloak\Services\Identity;
use Snairbef\Laracloak\Services\Jwt;
use Snairbef\Laracloak\Services\Oidc;
use Snairbef\Laracloak\Services\Revocation;
use Snairbef\Laracloak\Services\Token;
use Snairbef\Laracloak\Services\Userinfo;
use Snairbef\Laracloak\Support\Pkce;
use Snairbef\Laracloak\Support\State;

final class LaracloakServiceProvider extends ServiceProvider
{
    /**
     * Register package services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/laracloak.php',
            'laracloak',
        );

        $this->singletons();
    }

    /**
     * Bootstrap package services.
     */
    public function boot(): void
    {
        $this->publish();
        $this->routes();
        $this->guard();
        $this->provider();

        Authenticate::redirectUsing(
            fn () => route('laracloak.login'),
        );
    }

    /**
     * Register package singletons.
     */
    private function singletons(): void
    {
        foreach (
            [
                Client::class,
                Discovery::class,
                Token::class,
                Userinfo::class,
                Jwt::class,
                Identity::class,
                Revocation::class,
                State::class,
                Pkce::class,
                Oidc::class,
            ] as $service
        ) {
            $this->app->singleton($service);
        }
    }

    /**
     * Publish package configuration.
     */
    private function publish(): void
    {
        $this->publishes([
            __DIR__.'/../config/laracloak.php' => config_path('laracloak.php'),
        ], 'laracloak-config');
    }

    /**
     * Register package routes.
     */
    private function routes(): void
    {
        $this->loadRoutesFrom(
            __DIR__.'/../routes/web.php',
        );
    }

    /**
     * Register the Laracloak authentication guard.
     */
    private function guard(): void
    {
        Auth::extend(
            'laracloak',
            function (
                Application $app,
                string $name,
                array $config,
            ): Guard {
                $auth = $app->make('auth');

                $provider = $auth->createUserProvider(
                    $config['provider'] ?? null,
                );

                return new Guard(
                    $name,
                    $app->make(Identity::class),
                    $app->make('request'),
                    $app->make('session.store'),
                    $provider,
                    $app->make(Revocation::class),
                    $app->make(UserResolver::class),
                );
            },
        );
    }

    /**
     * Register the Laracloak user provider.
     */
    private function provider(): void
    {
        Auth::provider(
            'laracloak',
            function (
                Application $app,
                array $config,
            ): Provider {
                return new Provider(
                    $app->make(Identity::class),
                );
            },
        );
    }
}
