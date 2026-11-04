<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Exceptions;

use RuntimeException;
use Snairbef\Laracloak\Contracts\LaracloakException;

class AuthenticationException extends RuntimeException implements LaracloakException
{
}
