<?php

arch('it will not use debugging functions')
    ->expect(['dd', 'dump', 'ray'])
    ->each->not->toBeUsed();

arch('package source uses strict types')
    ->expect('Snairbef\Laracloak')
    ->toUseStrictTypes();

arch('services are final')
    ->expect('Snairbef\Laracloak\Services')
    ->toBeClasses()
    ->toBeFinal();

arch('support classes are final')
    ->expect('Snairbef\Laracloak\Support')
    ->toBeClasses()
    ->toBeFinal();

arch('authentication classes are final')
    ->expect('Snairbef\Laracloak\Auth')
    ->toBeClasses()
    ->toBeFinal();

arch('controllers are final')
    ->expect('Snairbef\Laracloak\Http\Controllers')
    ->toBeClasses()
    ->toBeFinal();

arch('exceptions extend runtime exception')
    ->expect('Snairbef\Laracloak\Exceptions\OidcException')
    ->toExtend(RuntimeException::class);

arch('package does not depend on debugging packages')
    ->expect('Snairbef\Laracloak')
    ->not->toUse('Symfony\Component\VarDumper');
