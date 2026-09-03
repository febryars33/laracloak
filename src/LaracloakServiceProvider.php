<?php

declare(strict_types=1);

namespace Snairbef\Laracloak;

use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use Snairbef\Laracloak\Auth\Guard;
use Snairbef\Laracloak\Auth\Provider;
use Snairbef\Laracloak\Auth\UserResolver;
use Snairbef\Laracloak\Contracts\Discovery as ContractsDiscovery;
use Snairbef\Laracloak\Contracts\Identity as ContractsIdentity;
use Snairbef\Laracloak\Contracts\Jwt as ContractsJwt;
use Snairbef\Laracloak\Contracts\Oidc as ContractsOidc;
use Snairbef\Laracloak\Contracts\Pkce as ContractsPkce;
use Snairbef\Laracloak\Contracts\Revocation as ContractsRevocation;
use Snairbef\Laracloak\Contracts\State as ContractsState;
use Snairbef\Laracloak\Contracts\Token as ContractsToken;
use Snairbef\Laracloak\Contracts\Userinfo as ContractsUserinfo;
use Snairbef\Laracloak\Contracts\UserResolver as ContractsUserResolver;
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

        $this->contracts();
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
                    $app->make(ContractsIdentity::class),
                    $app->make('session.store'),
                    $provider,
                    $app->make(ContractsRevocation::class),
                    $app->make(ContractsUserResolver::class),
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

    private function contracts(): void
    {
        $this->app->alias(
            Discovery::class,
            ContractsDiscovery::class,
        );

        $this->app->alias(
            Identity::class,
            ContractsIdentity::class,
        );

        $this->app->alias(
            Jwt::class,
            ContractsJwt::class,
        );

        $this->app->alias(
            Oidc::class,
            ContractsOidc::class,
        );

        $this->app->alias(
            Pkce::class,
            ContractsPkce::class,
        );

        $this->app->alias(
            Revocation::class,
            ContractsRevocation::class,
        );

        $this->app->alias(
            State::class,
            ContractsState::class,
        );

        $this->app->alias(
            Token::class,
            ContractsToken::class,
        );

        $this->app->alias(
            Userinfo::class,
            ContractsUserinfo::class,
        );

        $this->app->alias(
            UserResolver::class,
            ContractsUserResolver::class,
        );
    }
}
