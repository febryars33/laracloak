<?php

declare(strict_types=1);

namespace Snairbef\Laracloak\Contracts;

interface State
{
    public function generate(): string;
}
