<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Services;

use Snairbef\Laracloak\Contracts\Userinfo as Contract;
use Snairbef\Laracloak\Exceptions\AuthenticationException;
use Snairbef\Laracloak\Http\Client;

final class Userinfo implements Contract
{
    public function __construct(
        private readonly Client $client,
        private readonly Discovery $discovery,
    ) {}

    public function get(string $access): array
    {
        if (trim($access) === '') {
            throw new AuthenticationException('OIDC access token is missing.');
        }

        $profile = $this->client
            ->bearer(
                $this->discovery->get('userinfo_endpoint'),
                $access,
            )
            ->json();

        if (! is_array($profile)) {
            throw new AuthenticationException('Invalid OIDC userinfo response.');
        }

        return $profile;
    }
}
