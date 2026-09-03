<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Http;

use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use InvalidArgumentException;
use Snairbef\Laracloak\Exceptions\OidcException;

final class Client
{
    private function request(): PendingRequest
    {
        return Http::timeout(
            (int) config(
                'laracloak.http.timeout',
                10,
            ),
        )->connectTimeout(
            (int) config(
                'laracloak.http.connect_timeout',
                5,
            ),
        )->acceptJson();
    }

    public function get(string $url): Response
    {
        $this->validate($url);

        return $this->send(
            $this->request()->get($url),
        );
    }

    public function bearer(
        string $url,
        string $token,
    ): Response {
        $this->validate($url);

        return $this->send(
            $this->request()
                ->withToken($token)
                ->get($url),
        );
    }

    public function post(
        string $url,
        array $data = [],
    ): Response {
        $this->validate($url);

        return $this->send(
            $this->request()
                ->asForm()
                ->post($url, $data),
        );
    }

    private function send(Response $response): Response
    {
        if ($response->failed()) {
            throw OidcException::http($response);
        }

        return $response;
    }

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
