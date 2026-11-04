<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Exceptions;

use RuntimeException;
use Snairbef\Laracloak\Contracts\LaracloakException;

final class ConfigurationException extends RuntimeException implements LaracloakException {}
