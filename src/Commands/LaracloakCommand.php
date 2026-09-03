<?php

namespace Snairbef\Laracloak\Commands;

use Illuminate\Console\Command;

class LaracloakCommand extends Command
{
    public $signature = 'laracloak';

    public $description = 'My command';

    public function handle(): int
    {
        $this->comment('All done');

        return self::SUCCESS;
    }
}
