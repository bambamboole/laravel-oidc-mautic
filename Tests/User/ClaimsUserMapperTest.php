<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Tests\User;

use Mautic\CoreBundle\Helper\CoreParametersHelper;
use Mautic\UserBundle\Entity\User;
use MauticPlugin\LaravelOidcBundle\User\ClaimsUserMapper;
use PHPUnit\Framework\TestCase;

final class ClaimsUserMapperTest extends TestCase
{
    public function test_it_maps_standard_claims_with_default_paths(): void
    {
        $user = $this->mapper([])->apply(new User, [
            'email' => 'jane@example.com',
            'given_name' => 'Jane',
            'family_name' => 'Doe',
            'zoneinfo' => 'Europe/Berlin',
            'locale' => 'de',
        ]);

        self::assertSame('jane@example.com', $user->getUserIdentifier());
        self::assertSame('jane@example.com', $user->getEmail());
        self::assertSame('Jane', $user->getFirstName());
        self::assertSame('Doe', $user->getLastName());
        self::assertSame('Europe/Berlin', $user->getTimezone());
        self::assertSame('de', $user->getLocale());
    }

    public function test_it_honours_configured_claim_paths(): void
    {
        $user = $this->mapper([
            'oidc_username_claim' => 'preferred_username',
            'oidc_first_name_claim' => 'profile.first',
            'oidc_last_name_claim' => 'profile.last',
        ])->apply(new User, [
            'preferred_username' => 'jdoe',
            'email' => 'jane@example.com',
            'profile' => ['first' => 'Jane', 'last' => 'Doe'],
        ]);

        self::assertSame('jdoe', $user->getUserIdentifier());
        self::assertSame('Jane', $user->getFirstName());
        self::assertSame('Doe', $user->getLastName());
    }

    public function test_it_splits_the_name_claim_when_given_and_family_name_are_missing(): void
    {
        $user = $this->mapper([])->apply(new User, ['email' => 'jane@example.com', 'name' => 'Jane Marie Doe']);

        self::assertSame('Jane', $user->getFirstName());
        self::assertSame('Marie Doe', $user->getLastName());
    }

    public function test_it_falls_back_to_the_username_when_no_name_claim_exists(): void
    {
        $user = $this->mapper([])->apply(new User, ['email' => 'jane@example.com']);

        self::assertSame('jane', $user->getFirstName());
        self::assertSame('jane', $user->getLastName());
    }

    public function test_it_keeps_existing_timezone_and_locale_when_claims_are_absent(): void
    {
        $existing = (new User)->setTimezone('UTC')->setLocale('en_US');

        $user = $this->mapper([])->apply($existing, ['email' => 'jane@example.com', 'name' => 'Jane Doe']);

        self::assertSame('UTC', $user->getTimezone());
        self::assertSame('en_US', $user->getLocale());
    }

    /**
     * @param  array<string, string|null>  $parameters
     */
    private function mapper(array $parameters): ClaimsUserMapper
    {
        $helper = $this->createMock(CoreParametersHelper::class);
        $helper->method('get')->willReturnCallback(static fn (string $key): ?string => $parameters[$key] ?? null);

        return new ClaimsUserMapper($helper);
    }
}
