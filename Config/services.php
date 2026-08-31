<?php

declare(strict_types=1);

use Mautic\CoreBundle\DependencyInjection\MauticCoreExtension;
use MauticPlugin\LaravelOidcBundle\Integration\LaravelOidcIntegration;
use MauticPlugin\LaravelOidcBundle\Security\OidcBearerTokenStorage;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

return function (ContainerConfigurator $configurator): void {
    $services = $configurator->services()
        ->defaults()
        ->autowire()
        ->autoconfigure()
        ->public();

    $services->load('MauticPlugin\\LaravelOidcBundle\\', '../')
        ->exclude('../{'.implode(',', [...MauticCoreExtension::DEFAULT_EXCLUDES, 'Claims', 'Discovery', 'Security', 'User']).'}');

    $services->alias('mautic.integration.laraveloidc', LaravelOidcIntegration::class);

    // Lets a provider-issued Bearer JWT authenticate API requests: the storage
    // decoration synthesizes an access token when the local lookup misses.
    $services->set(OidcBearerTokenStorage::class)
        ->decorate('fos_oauth_server.storage')
        ->args([
            service('fos_oauth_server.client_manager'),
            service('fos_oauth_server.access_token_manager'),
            service('fos_oauth_server.refresh_token_manager'),
            service('fos_oauth_server.auth_code_manager'),
            service('fos_oauth_server.user_provider')->nullOnInvalid(),
            service('security.password_hasher_factory')->nullOnInvalid(),
            service('mautic.helper.core_parameters'),
            service('mautic.helper.integration'),
            service('mautic.helper.cache_storage')->nullOnInvalid(),
        ]);
};
