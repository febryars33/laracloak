<?php

use Illuminate\Support\Facades\Http;

it('registers the login route', function () {
    // Mock the HTTP request to prevent actual external calls
    Http::fake([
        'http://localhost:8000/.well-known/openid-configuration' => Http::response([
            'authorization_endpoint' => 'https://provider.example.com/authorize',
            'token_endpoint' => 'https://provider.example.com/token',
            'userinfo_endpoint' => 'https://provider.example.com/userinfo',
        ]),
    ]);

    $this->get('/auth/login')
        ->assertRedirect();
});

it('registers the callback route', function () {
    $this->get('/auth/callback')
        ->assertStatus(500);
});

it('does not allow GET logout', function () {
    $this->get('/auth/logout')
        ->assertMethodNotAllowed();
});

it('registers POST logout', function () {
    $this->post('/auth/logout')
        ->assertRedirect();
});

it('registers back-channel logout', function () {
    $this->post('/auth/backchannel-logout')
        ->assertOk();
});
