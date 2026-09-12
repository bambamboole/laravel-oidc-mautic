<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Tests\Integration;

use MauticPlugin\LaravelOidcBundle\Integration\LaravelOidcIntegration;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

final class AuthLoginStateTest extends TestCase
{
    /**
     * The state guards the callback against CSRF. AbstractIntegration derives
     * it from uniqid(mt_rand()), which is time-based and not a CSPRNG.
     */
    public function test_the_state_is_unpredictable_and_does_not_come_from_the_clock(): void
    {
        $integration = (new ReflectionClass(LaravelOidcIntegration::class))->newInstanceWithoutConstructor();

        $states = [];

        for ($i = 0; $i < 50; $i++) {
            $states[] = $integration->getAuthLoginState();
        }

        self::assertCount(50, array_unique($states));

        foreach ($states as $state) {
            self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $state);
        }

        // 43 base64url characters of random_bytes(32), not the 40 hex
        // characters the inherited sha1 would produce.
    }
}
