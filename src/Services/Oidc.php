<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Services;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Snairbef\Laracloak\Contracts\Discovery;
use Snairbef\Laracloak\Contracts\Jwt;
use Snairbef\Laracloak\Contracts\Oidc as Contract;
use Snairbef\Laracloak\Contracts\Pkce;
use Snairbef\Laracloak\Contracts\Revocation;
use Snairbef\Laracloak\Contracts\State;
use Snairbef\Laracloak\Contracts\Token;
use Snairbef\Laracloak\Contracts\Userinfo;
use Snairbef\Laracloak\Exceptions\OidcException;

final class Oidc implements Contract
{
    public function __construct(
        private readonly Discovery $discovery,
        private readonly Token $token,
        private readonly Userinfo $userinfo,
        private readonly Jwt $jwt,
        private readonly State $state,
        private readonly Pkce $pkce,
        private readonly Revocation $revocation,
    ) {}

    public function login(
        Request $request,
    ): RedirectResponse {
        $session = $request->session();

        $verifier = $this->pkce->generate();

        $flow = [
            'state' => $this->state->generate(),
            'nonce' => $this->state->generate(),
            'verifier' => $verifier,
        ];

        $session->put(
            $this->key('flow'),
            $flow,
        );

        /*
         * Force persistence before leaving the application.
         */
        $session->save();

        Log::info('Laracloak OIDC login started.', [
            'session' => $session->getId(),
            'flow' => $session->has($this->key('flow')),
            'state' => $flow['state'],
        ]);

        $query = http_build_query([
            'response_type' => 'code',
            'client_id' => $this->client(),
            'redirect_uri' => $this->redirect(),
            'scope' => $this->scope(),
            'state' => $flow['state'],
            'nonce' => $flow['nonce'],
            'code_challenge' => $this->pkce->challenge(
                $verifier,
            ),
            'code_challenge_method' => 'S256',
        ]);

        return redirect()->away(
            $this->discovery->get('authorization_endpoint')
                .'?'
                .$query,
        );
    }

    public function callback(
        Request $request,
    ): RedirectResponse {
        $this->error($request);

        $session = $request->session();

        Log::info('Laracloak OIDC callback received.', [
            'session' => $session->getId(),
            'flow' => $session->has($this->key('flow')),
            'state' => $request->query('state'),
        ]);

        $flow = $session->get(
            $this->key('flow'),
        );

        if (! is_array($flow)) {
            Log::error('Laracloak OIDC flow missing.', [
                'session' => $session->getId(),
                'session_key' => $this->key('flow'),
                'session_data' => $session->all(),
            ]);

            throw OidcException::authentication(
                'OIDC authentication session has expired.',
            );
        }

        $this->state(
            $request,
            $flow,
        );

        $code = $request->query('code');

        if (! is_string($code) || $code === '') {
            throw OidcException::authentication(
                'OIDC authorization code is missing.',
            );
        }

        $nonce = $flow['nonce'] ?? null;
        $verifier = $flow['verifier'] ?? null;

        if (
            ! is_string($nonce)
            || ! is_string($verifier)
        ) {
            throw OidcException::authentication(
                'Invalid OIDC authentication session.',
            );
        }

        $tokens = $this->token->exchange(
            $code,
            $verifier,
        );

        $idToken = $tokens['id_token'] ?? null;

        if (! is_string($idToken) || $idToken === '') {
            throw OidcException::authentication(
                'OIDC ID token is missing.',
            );
        }

        $claims = (array) $this->jwt->validate(
            $idToken,
        );

        $this->nonce(
            $claims,
            $nonce,
        );

        $access = $tokens['access_token'] ?? null;

        if (! is_string($access) || $access === '') {
            throw OidcException::authentication(
                'OIDC access token is missing.',
            );
        }

        $profile = $this->userinfo->get($access);

        $this->subject(
            $claims,
            $profile,
        );

        $subject = (string) $profile['sub'];

        $this->revocation->clear($subject);

        $session->put(
            $this->key('token'),
            $tokens,
        );

        $session->put(
            $this->key('user'),
            $profile,
        );

        $session->put(
            $this->key('identity_at'),
            now()->timestamp,
        );

        $session->forget(
            $this->key('flow'),
        );

        $session->save();

        Log::info('Laracloak OIDC callback completed.', [
            'session' => $session->getId(),
            'subject' => $subject,
            'authenticated' => $session->has(
                $this->key('user'),
            ),
        ]);

        return redirect()->intended('/');
    }

    public function logout(
        Request $request,
    ): RedirectResponse {
        $tokens = $this->tokens($request);

        $url = is_array($tokens)
            ? $this->logoutUrl($tokens)
            : null;

        Log::info('Laracloak OIDC logout.', [
            'session' => $request->session()->getId(),
            'has_tokens' => is_array($tokens),
            'has_url' => $url !== null,
            'endpoint' => is_string($url)
                ? parse_url($url, PHP_URL_PATH)
                : null,
            'host' => is_string($url)
                ? parse_url($url, PHP_URL_HOST)
                : null,
        ]);

        $this->clear($request);

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return $url !== null
            ? redirect()->away($url)
            : redirect('/');
    }

    public function user(
        Request $request,
    ): ?array {
        $user = $request->session()->get(
            $this->key('user'),
        );

        return is_array($user)
            ? $user
            : null;
    }

    public function tokens(
        Request $request,
    ): ?array {
        $tokens = $request->session()->get(
            $this->key('token'),
        );

        return is_array($tokens)
            ? $tokens
            : null;
    }

    public function refresh(
        Request $request,
    ): ?array {
        $tokens = $this->tokens($request);

        if (! is_array($tokens)) {
            return null;
        }

        $refresh = $tokens['refresh_token'] ?? null;

        if (! is_string($refresh) || $refresh === '') {
            return null;
        }

        $tokens = $this->token->refresh($refresh);

        $request->session()->put(
            $this->key('token'),
            $tokens,
        );

        $request->session()->save();

        return $tokens;
    }

    public function backchannel(
        mixed $token,
    ): void {
        if (! is_string($token)) {
            throw OidcException::authentication(
                'OIDC logout token is missing.',
            );
        }

        $claims = $this->jwt->logout($token);

        $subject = $claims['sub'] ?? null;

        if (
            ! is_string($subject)
            || $subject === ''
        ) {
            return;
        }

        $this->revocation->revoke($subject);
    }

    private function state(
        Request $request,
        array $flow,
    ): void {
        $state = $request->query('state');

        if (
            ! is_string($state)
            || $state === ''
            || ! is_string($flow['state'] ?? null)
            || ! hash_equals($flow['state'], $state)
        ) {
            throw OidcException::authentication(
                'Invalid OIDC state.',
            );
        }
    }

    private function nonce(
        array $claims,
        string $expected,
    ): void {
        $actual = $claims['nonce'] ?? null;

        if (
            ! is_string($actual)
            || ! hash_equals($expected, $actual)
        ) {
            throw OidcException::authentication(
                'Invalid OIDC nonce.',
            );
        }
    }

    private function subject(
        array $claims,
        array $profile,
    ): void {
        $expected = $claims['sub'] ?? null;
        $actual = $profile['sub'] ?? null;

        if (
            ! is_string($expected)
            || $expected === ''
        ) {
            throw OidcException::authentication(
                'OIDC ID token subject is missing.',
            );
        }

        if (
            ! is_string($actual)
            || $actual === ''
        ) {
            throw OidcException::authentication(
                'OIDC UserInfo subject is missing.',
            );
        }

        if (! hash_equals($expected, $actual)) {
            throw OidcException::authentication(
                'OIDC subject mismatch.',
            );
        }
    }

    private function error(
        Request $request,
    ): void {
        $error = $request->query('error');

        if (! is_string($error) || $error === '') {
            return;
        }

        $request->session()->forget(
            $this->key('flow'),
        );

        throw OidcException::authentication(
            'OIDC authentication failed.',
        );
    }

    private function logoutUrl(
        array $tokens,
    ): ?string {
        try {
            $endpoint = $this->discovery->get(
                'end_session_endpoint',
            );
        } catch (\Throwable) {
            $endpoint = config(
                'laracloak.logout_endpoint',
            );
        }

        if (
            ! is_string($endpoint)
            || trim($endpoint) === ''
        ) {
            return null;
        }

        $query = [];

        $idToken = $tokens['id_token'] ?? null;

        if (
            is_string($idToken)
            && $idToken !== ''
        ) {
            $query['id_token_hint'] = $idToken;
        }

        $redirect = config(
            'laracloak.post_logout_redirect_uri',
        );

        if (
            is_string($redirect)
            && $redirect !== ''
        ) {
            $query['post_logout_redirect_uri'] = $redirect;
        }

        $query['client_id'] = $this->client();

        return $endpoint
            .(str_contains($endpoint, '?') ? '&' : '?')
            .http_build_query(
                $query,
                '',
                '&',
                PHP_QUERY_RFC3986,
            );
    }

    private function clear(
        Request $request,
    ): void {
        $request->session()->forget([
            $this->key('flow'),
            $this->key('token'),
            $this->key('user'),
            $this->key('identity_at'),
        ]);
    }

    private function key(
        string $name,
    ): string {
        return (string) config(
            "laracloak.session.{$name}",
        );
    }

    private function client(): string
    {
        return $this->value(
            config('laracloak.client.id'),
            'laracloak.client.id',
        );
    }

    private function redirect(): string
    {
        return $this->value(
            config('laracloak.redirect.login'),
            'laracloak.redirect.login',
        );
    }

    private function scope(): string
    {
        $scopes = config(
            'laracloak.scopes',
            [],
        );

        if (! is_array($scopes)) {
            throw OidcException::configuration(
                'OIDC scopes must be an array.',
            );
        }

        return implode(
            ' ',
            array_filter(
                array_map(
                    static fn (mixed $scope): string => is_string($scope)
                        ? trim($scope)
                        : '',
                    $scopes,
                ),
            ),
        );
    }

    private function value(
        mixed $value,
        string $key,
    ): string {
        if (
            ! is_string($value)
            || trim($value) === ''
        ) {
            throw OidcException::configuration(
                "Laracloak configuration [{$key}] is missing.",
            );
        }

        return trim($value);
    }
}
