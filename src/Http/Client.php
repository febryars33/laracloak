<?php

namespace Snairbef\Laracloak\Http;

use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use InvalidArgumentException;
use Snairbef\Laracloak\Exceptions\OidcException;

final class Client
{
    /**
     * Create a configured HTTP client.
     */
    private function request(): PendingRequest
    {
        return Http::timeout(
            (int) config('laracloak.http.timeout', 10),
        )->connectTimeout(
            (int) config('laracloak.http.connect_timeout', 5),
        )->acceptJson();
    }

    /**
     * Send a GET request.
     */
    public function get(string $url): Response
    {
        $this->validate($url);

        return $this->request()
            ->get($url)
            ->throw(fn(Response $response) => OidcException::http($response));
    }

    /**
     * Send an authenticated GET request.
     */
    public function bearer(string $url, string $token): Response
    {
        $this->validate($url);

        return $this->request()
            ->withToken($token)
            ->get($url)
            ->throw(fn(Response $response) => OidcException::http($response));
    }

    /**
     * Send a POST request.
     *
     * @param  array<string, mixed>  $data
     */
    public function post(string $url, array $data = []): Response
    {
        $this->validate($url);

        return $this->request()
            ->asForm()
            ->post($url, $data)
            ->throw(fn(Response $response) => OidcException::http($response));
    }

    /**
     * Validate an absolute URL.
     */
    private function validate(string $url): void
    {
        $url = trim($url);

        if ($url === '') {
            throw new InvalidArgumentException(
                'Laracloak HTTP request URL cannot be empty.',
            );
        }

        if (! filter_var($url, FILTER_VALIDATE_URL)) {
            throw new InvalidArgumentException(
                "Laracloak HTTP request URL must be absolute: {$url}",
            );
        }
    }
}
