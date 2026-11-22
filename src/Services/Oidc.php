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
use Snairbef\Laracloak\Contracts\Replay;
use Snairbef\Laracloak\Contracts\Revocation;
use Snairbef\Laracloak\Contracts\State;
use Snairbef\Laracloak\Contracts\Token;
use Snairbef\Laracloak\Contracts\Userinfo;
use Snairbef\Laracloak\Exceptions\AuthenticationException;
use Snairbef\Laracloak\Exceptions\ConfigurationException;

final class Oidc implements Contract
{
    public function __construct(
        private readonly Discovery $discovery,
        private readonly Token $token,
        private readonly Userinfo $userinfo,
        private readonly Jwt $jwt,
        private readonly Replay $replay,
        private readonly State $state,
        private readonly Pkce $pkce,
        private readonly Revocation $revocation,
    ) {}

    public function login(
        Request $request,
    ): RedirectResponse {
        $session = $request->session();

        $verifier = $this->pkce->generate();
        $now = now()->timestamp;
        $state = $this->state->generate();
        $flows = array_filter(
            $this->flows($request),
            static fn (array $flow): bool => is_numeric($flow['expires_at'] ?? null)
                && (int) $flow['expires_at'] > $now,
        );

        $flow = [
            'id' => bin2hex(random_bytes(8)),
            'state' => $state,
            'nonce' => $this->state->generate(),
            'verifier' => $verifier,
            'expires_at' => $now + $this->flowTtl(),
        ];

        $flows[$state] = $flow;

        $limit = max(
            1,
            (int) config('laracloak.flow.limit', 5),
        );

        if (count($flows) > $limit) {
            $flows = array_slice($flows, -$limit, null, true);
        }

        $session->put(
            $this->key('flow'),
            $flows,
        );

        /*
         * Force persistence before leaving the application.
         */
        $session->save();

        Log::info('Laracloak OIDC login started.', [
            'flow_id' => $flow['id'],
        ]);

        $query = http_build_query([
            'response_type' => 'code',
            'client_id' => $this->client(),
            'redirect_uri' => $this->redirect(),
            'scope' => $this->scope(),
            'state' => $state,
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
        $session = $request->session();
        $state = $request->query('state');
        $flows = $this->flows($request);
        $flow = is_string($state)
            ? ($flows[$state] ?? null)
            : null;

        if (
            ! is_string($state)
            || $state === ''
            || ! is_array($flow)
            || ! is_string($flow['state'] ?? null)
            || ! hash_equals($flow['state'], $state)
        ) {
            throw new AuthenticationException(
                'Invalid OIDC state.',
            );
        }

        $expires = $flow['expires_at'] ?? null;

        if (
            ! is_numeric($expires)
            || (int) $expires <= now()->timestamp
        ) {
            $this->consumeFlow($request, $state, $flows);

            throw new AuthenticationException(
                'OIDC authentication session has expired.',
            );
        }

        $this->consumeFlow($request, $state, $flows);
        $this->error($request);

        $flowId = is_string($flow['id'] ?? null)
            ? $flow['id']
            : 'unknown';

        Log::info('Laracloak OIDC callback received.', [
            'flow_id' => $flowId,
            'has_code' => is_string($request->query('code')),
            'has_error' => is_string($request->query('error')),
        ]);

        $code = $request->query('code');

        if (! is_string($code) || $code === '') {
            throw new AuthenticationException(
                'OIDC authorization code is missing.',
            );
        }

        $nonce = $flow['nonce'] ?? null;
        $verifier = $flow['verifier'] ?? null;

        if (
            ! is_string($nonce)
            || ! is_string($verifier)
        ) {
            throw new AuthenticationException('Invalid OIDC authentication session.');
        }

        Log::info('Laracloak OIDC token exchange started.', [
            'flow_id' => $flowId,
        ]);

        $tokens = $this->token->exchange(
            $code,
            $verifier,
        );

        Log::info('Laracloak OIDC token exchange completed.', [
            'flow_id' => $flowId,
            'has_id_token' => is_string($tokens['id_token'] ?? null),
            'has_access_token' => is_string($tokens['access_token'] ?? null),
            'has_refresh_token' => is_string($tokens['refresh_token'] ?? null),
        ]);

        $idToken = $tokens['id_token'] ?? null;

        if (! is_string($idToken) || $idToken === '') {
            throw new AuthenticationException('OIDC ID token is missing.');
        }

        $claims = (array) $this->jwt->validate(
            $idToken,
        );

        Log::info('Laracloak OIDC ID token validated.', [
            'flow_id' => $flowId,
        ]);

        $this->nonce(
            $claims,
            $nonce,
        );

        Log::info('Laracloak OIDC nonce validated.', [
            'flow_id' => $flowId,
        ]);

        $access = $tokens['access_token'] ?? null;

        if (! is_string($access) || $access === '') {
            throw new AuthenticationException('OIDC access token is missing.');
        }

        Log::info('Laracloak OIDC UserInfo request started.', [
            'flow_id' => $flowId,
        ]);

        $profile = $this->userinfo->get($access);

        $this->subject(
            $claims,
            $profile,
        );

        Log::info('Laracloak OIDC UserInfo validated.', [
            'flow_id' => $flowId,
        ]);

        $subject = (string) $profile['sub'];

        $sid = is_string($claims['sid'] ?? null) && trim($claims['sid']) !== ''
            ? trim($claims['sid'])
            : null;

        if ($sid !== null) {
            $this->revocation->clear($sid);
        }

        $this->revocation->clear($subject);
        $this->revocation->clear('legacy:'.$subject);

        $session->regenerate();

        if ($sid !== null) {
            $session->put(
                $this->key('sid'),
                $sid,
            );
        } else {
            $session->forget(
                $this->key('sid'),
            );
        }

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

        $session->save();

        Log::info('Laracloak OIDC callback completed.', [
            'flow_id' => $flowId,
            'authenticated' => $session->has(
                $this->key('user'),
            ),
            'has_sid' => $sid !== null,
            'has_refresh_token' => is_string(
                $tokens['refresh_token'] ?? null,
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

        Log::info('Laracloak OIDC logout started.', [
            'has_tokens' => is_array($tokens),
            'redirect_to_idp' => $url !== null,
            'has_id_token_hint' => is_string(
                $tokens['id_token'] ?? null,
            ),
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
            throw new AuthenticationException('OIDC logout token is missing.');
        }

        $claims = $this->jwt->logout($token);

        $id = $claims['jti'] ?? null;
        $expires = $claims['exp'] ?? null;

        if (
            ! is_string($id)
            || trim($id) === ''
            || (! is_int($expires) && ! is_float($expires))
            || ! is_finite((float) $expires)
        ) {
            throw new AuthenticationException('OIDC logout token replay claims are invalid.');
        }

        $this->replay->once(
            $id,
            (int) $expires,
            function () use ($claims): void {
                $sid = $claims['sid'] ?? null;
                $subject = $claims['sub'] ?? null;

                if (is_string($sid) && trim($sid) !== '') {
                    $this->revocation->revoke(trim($sid));
                } elseif (is_string($subject) && trim($subject) !== '') {
                    $this->revocation->revoke(trim($subject));
                    $this->revocation->revoke('legacy:'.trim($subject));
                } else {
                    throw new AuthenticationException('OIDC logout token subject is missing.');
                }

                Log::info('Laracloak OIDC back-channel logout processed.', [
                    'has_sid' => is_string($sid) && trim($sid) !== '',
                    'has_subject' => is_string($subject) && trim($subject) !== '',
                ]);
            },
        );
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
            throw new AuthenticationException('Invalid OIDC nonce.');
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
            throw new AuthenticationException('OIDC ID token subject is missing.');
        }

        if (
            ! is_string($actual)
            || $actual === ''
        ) {
            throw new AuthenticationException('OIDC UserInfo subject is missing.');
        }

        if (! hash_equals($expected, $actual)) {
            throw new AuthenticationException('OIDC subject mismatch.');
        }
    }

    private function error(Request $request): void
    {
        $error = $request->query('error');

        if (! is_string($error) || $error === '') {
            return;
        }

        throw new AuthenticationException('OIDC authentication failed.');
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    private function flows(Request $request): array
    {
        $flows = $request->session()->get(
            $this->key('flow'),
            [],
        );

        if (! is_array($flows) || array_key_exists('state', $flows)) {
            return [];
        }

        $valid = [];

        foreach ($flows as $state => $flow) {
            if (is_string($state) && is_array($flow)) {
                $valid[$state] = $flow;
            }
        }

        return $valid;
    }

    /**
     * @param  array<string, array<string, mixed>>  $flows
     */
    private function consumeFlow(
        Request $request,
        string $state,
        array $flows,
    ): void {
        unset($flows[$state]);

        if ($flows === []) {
            $request->session()->forget(
                $this->key('flow'),
            );
        } else {
            $request->session()->put(
                $this->key('flow'),
                $flows,
            );
        }

        $request->session()->save();
    }

    private function flowTtl(): int
    {
        return max(
            1,
            (int) config('laracloak.flow.ttl', 600),
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
            $this->key('sid'),
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
            throw new ConfigurationException('OIDC scopes must be an array.');
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
            throw new ConfigurationException("Laracloak configuration [{$key}] is missing.");
        }

        return trim($value);
    }
}
