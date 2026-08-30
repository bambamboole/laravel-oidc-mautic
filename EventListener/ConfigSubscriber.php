<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\EventListener;

use Mautic\ConfigBundle\ConfigEvents;
use Mautic\ConfigBundle\Event\ConfigBuilderEvent;
use MauticPlugin\LaravelOidcBundle\Form\Type\ConfigType;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

class ConfigSubscriber implements EventSubscriberInterface
{
    /**
     * @return array<string, array{0: string, 1: int}>
     */
    public static function getSubscribedEvents(): array
    {
        return [
            ConfigEvents::CONFIG_ON_GENERATE => ['onConfigGenerate', 0],
        ];
    }

    public function onConfigGenerate(ConfigBuilderEvent $event): void
    {
        $event->addForm([
            'bundle' => 'LaravelOidcBundle',
            'formAlias' => 'laraveloidcconfig',
            'formTheme' => '@LaravelOidc/FormTheme/Config/_config_laraveloidcconfig_widget.html.twig',
            'formType' => ConfigType::class,
            'parameters' => $event->getParametersFromConfig('LaravelOidcBundle'),
        ]);
    }
}
