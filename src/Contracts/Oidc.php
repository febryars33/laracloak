<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Contracts;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

interface Oidc
{
    public function login(Request $request): RedirectResponse;

    public function callback(Request $request): RedirectResponse;

    public function logout(Request $request): RedirectResponse;

    public function backchannel(?string $token): void;
}
