<?php

namespace Snairbef\Laracloak\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @see \Snairbef\Laracloak\Laracloak
 */
class Laracloak extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'laracloak';
    }
}
