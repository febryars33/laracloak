<?php

namespace Snairbef\Laracloak\Services;

use Snairbef\Laracloak\Exceptions\OidcException;
use Snairbef\Laracloak\Http\Client;

final class Userinfo
{
    public function __construct(
        private readonly Client $client,
        private readonly Discovery $discovery,
    ) {}

    public function get(string $access): array
    {
        if (trim($access) === '') {
            throw OidcException::authentication(
                'OIDC access token is missing.',
            );
        }

        $profile = $this->client
            ->bearer(
                $this->discovery->get('userinfo_endpoint'),
                $access,
            )
            ->json();

        if (! is_array($profile)) {
            throw OidcException::authentication(
                'Invalid OIDC userinfo response.',
            );
        }

        return $profile;
    }
}
