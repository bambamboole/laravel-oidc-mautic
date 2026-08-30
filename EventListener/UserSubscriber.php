<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\EventListener;

use Mautic\CoreBundle\Helper\CoreParametersHelper;
use Mautic\UserBundle\Entity\User;
use Mautic\UserBundle\Event\AuthenticationEvent;
use Mautic\UserBundle\UserEvents;
use MauticPlugin\LaravelOidcBundle\Integration\LaravelOidcIntegration;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

class UserSubscriber implements EventSubscriberInterface
{
    public function __construct(private readonly CoreParametersHelper $coreParametersHelper) {}

    /**
     * @return array<string, array{0: string, 1: int}>
     */
    public static function getSubscribedEvents(): array
    {
        return [
            UserEvents::USER_PRE_AUTHENTICATION => ['onUserAuthentication', 0],
        ];
    }

    public function onUserAuthentication(AuthenticationEvent $event): void
    {
        if ($event->getAuthenticatingService() !== LaravelOidcIntegration::NAME) {
            return;
        }

        $integration = $event->getIntegration(LaravelOidcIntegration::NAME);

        if (! $integration instanceof LaravelOidcIntegration) {
            throw new \RuntimeException('The OpenID Connect integration is not available.');
        }

        $integration->setCoreParametersHelper($this->coreParametersHelper);
        $integration->setUserProvider($event->getUserProvider());

        if (! $event->isLoginCheck()) {
            $event->setResponse(new RedirectResponse($integration->getAuthLoginUrl()));

            return;
        }

        $user = $integration->ssoAuthCallback();

        if (! $user instanceof User) {
            throw new AuthenticationException('mautic.user.auth.error.invalidlogin');
        }

        $event->setIsAuthenticated(LaravelOidcIntegration::NAME, $user, $integration->shouldAutoCreateNewUser());
    }
}
