<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Tests\Security;

use MauticPlugin\LaravelOidcBundle\Claims\ClaimRequirement;
use MauticPlugin\LaravelOidcBundle\Security\ClaimsNotSatisfiedException;
use PHPUnit\Framework\TestCase;

final class ClaimsNotSatisfiedExceptionTest extends TestCase
{
    /**
     * Mautic stores the failure in the session and the login page reads it back
     * to render the message, so the exception has to survive a round trip.
     */
    public function test_it_keeps_the_unmet_requirements_through_the_session(): void
    {
        $exception = new ClaimsNotSatisfiedException([
            new ClaimRequirement('groups', 'staff'),
            new ClaimRequirement('email_verified', 'true'),
        ]);

        $restored = unserialize(serialize($exception));

        self::assertInstanceOf(ClaimsNotSatisfiedException::class, $restored);
        self::assertSame($exception->getMessageKey(), $restored->getMessageKey());
        self::assertSame($exception->getMessageData(), $restored->getMessageData());
    }
}
