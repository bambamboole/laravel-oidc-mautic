<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Tests\EventListener;

use Mautic\CoreBundle\Helper\CoreParametersHelper;
use Mautic\UserBundle\Entity\User;
use Mautic\UserBundle\Event\AuthenticationEvent;
use Mautic\UserBundle\Security\Authentication\Token\PluginToken;
use Mautic\UserBundle\Security\Provider\UserProvider;
use Mautic\UserBundle\UserEvents;
use MauticPlugin\LaravelOidcBundle\EventListener\UserSubscriber;
use MauticPlugin\LaravelOidcBundle\Integration\LaravelOidcIntegration;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

final class UserSubscriberTest extends TestCase
{
    private UserSubscriber $subscriber;

    private LaravelOidcIntegration&MockObject $integration;

    private UserProvider&MockObject $userProvider;

    protected function setUp(): void
    {
        $this->subscriber = new UserSubscriber($this->createMock(CoreParametersHelper::class));
        $this->integration = $this->createMock(LaravelOidcIntegration::class);
        $this->userProvider = $this->createMock(UserProvider::class);
    }

    public function test_it_listens_to_pre_authentication(): void
    {
        self::assertSame(['onUserAuthentication', 0], UserSubscriber::getSubscribedEvents()[UserEvents::USER_PRE_AUTHENTICATION]);
    }

    public function test_it_redirects_to_the_provider_on_login(): void
    {
        $this->integration->method('getAuthLoginUrl')->willReturn('https://idp.test/oauth/authorize?state=x');

        $event = $this->event(isLoginCheck: false);

        $this->subscriber->onUserAuthentication($event);

        $response = $event->getResponse();
        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('https://idp.test/oauth/authorize?state=x', $response->getTargetUrl());
        self::assertFalse($event->isAuthenticated());
    }

    public function test_it_authenticates_the_user_returned_by_the_callback(): void
    {
        $user = (new User)->setUsername('jane@example.com');
        $this->integration->method('ssoAuthCallback')->willReturn($user);
        $this->integration->method('shouldAutoCreateNewUser')->willReturn(true);
        $this->userProvider->expects(self::once())->method('saveUser')->with($user, true)->willReturn($user);

        $event = $this->event(isLoginCheck: true);

        $this->subscriber->onUserAuthentication($event);

        self::assertTrue($event->isAuthenticated());
        self::assertSame($user, $event->getUser());
    }

    public function test_it_ignores_other_authenticating_services(): void
    {
        $this->integration->expects(self::never())->method('getAuthLoginUrl');

        $event = $this->event(isLoginCheck: false, service: 'SomethingElse');

        $this->subscriber->onUserAuthentication($event);

        self::assertNull($event->getResponse());
    }

    private function event(bool $isLoginCheck, string $service = LaravelOidcIntegration::NAME): AuthenticationEvent
    {
        return new AuthenticationEvent(
            null,
            new PluginToken('main', $service),
            $this->userProvider,
            new Request,
            $isLoginCheck,
            $service,
            [LaravelOidcIntegration::NAME => $this->integration],
        );
    }
}
