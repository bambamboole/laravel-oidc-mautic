<?php

declare(strict_types=1);

use Mautic\CoreBundle\DependencyInjection\MauticCoreExtension;
use MauticPlugin\LaravelOidcBundle\Integration\LaravelOidcIntegration;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $configurator): void {
    $services = $configurator->services()
        ->defaults()
        ->autowire()
        ->autoconfigure()
        ->public();

    $services->load('MauticPlugin\\LaravelOidcBundle\\', '../')
        ->exclude('../{'.implode(',', [...MauticCoreExtension::DEFAULT_EXCLUDES, 'Claims', 'Discovery', 'Security', 'User']).'}');

    $services->alias('mautic.integration.laraveloidc', LaravelOidcIntegration::class);
};
