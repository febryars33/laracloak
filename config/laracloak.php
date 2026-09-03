<?php

use App\Models\User;

return [

    'issuer' => env(
        'LARACLOAK_ISSUER',
        'http://localhost:8000',
    ),

    'client' => [
        'id' => env('LARACLOAK_CLIENT_ID'),
        'secret' => env('LARACLOAK_CLIENT_SECRET'),
    ],

    'redirect' => [
        'login' => env(
            'LARACLOAK_REDIRECT_URI',
            'http://localhost:8001/auth/callback',
        ),
    ],

    'authentication' => [
        'method' => env(
            'LARACLOAK_AUTHENTICATION_METHOD',
            'client_secret_post',
        ),
    ],

    'scopes' => [
        'openid',
        'profile',
        'email',
    ],

    'identity' => [
        'ttl' => env(
            'LARACLOAK_IDENTITY_TTL',
            30,
        ),
    ],

    'lock' => [
        'seconds' => env(
            'LARACLOAK_LOCK_SECONDS',
            20,
        ),

        'block' => env(
            'LARACLOAK_LOCK_BLOCK',
            5,
        ),
    ],

    'http' => [
        'timeout' => env(
            'LARACLOAK_HTTP_TIMEOUT',
            10,
        ),

        'connect_timeout' => env(
            'LARACLOAK_HTTP_CONNECT_TIMEOUT',
            5,
        ),
    ],

    'user' => [
        'model' => env(
            'LARACLOAK_USER_MODEL',
            User::class
        ),

        'provision' => env(
            'LARACLOAK_USER_PROVISION',
            true,
        ),
    ],

    'session' => [
        'flow' => 'laracloak.flow',
        'token' => 'laracloak.token',
        'user' => 'laracloak.user',
        'identity_at' => 'laracloak.identity_at',
    ],

    'logout_endpoint' => env(
        'LARACLOAK_LOGOUT_ENDPOINT',
        'http://localhost:8000/oauth/logout',
    ),

    'post_logout_redirect_uri' => env(
        'LARACLOAK_POST_LOGOUT_REDIRECT_URI',
        'http://localhost:8001/',
    ),
];
