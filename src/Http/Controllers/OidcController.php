<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Log;
use Snairbef\Laracloak\Contracts\Oidc;
use Snairbef\Laracloak\Exceptions\AuthenticationException;

final class OidcController extends Controller
{
    public function __construct(
        private readonly Oidc $oidc,
    ) {}

    public function login(
        Request $request,
    ): RedirectResponse {
        return $this->oidc->login($request);
    }

    public function callback(
        Request $request,
    ): RedirectResponse {
        return $this->oidc->callback($request);
    }

    public function logout(
        Request $request,
    ): RedirectResponse {
        return $this->oidc->logout($request);
    }

    public function backchannel(
        Request $request,
    ): JsonResponse {
        try {
            $this->oidc->backchannel(
                $request->input('logout_token'),
            );

            return response()->json(null, 200);
        } catch (AuthenticationException $e) {
            Log::warning(
                'Laracloak back-channel logout rejected.',
                [
                    'exception' => $e::class,
                ],
            );

            return response()->json(null, 400);
        }
    }
}
