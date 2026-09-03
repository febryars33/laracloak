<?php

it('registers the login route', function () {
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
