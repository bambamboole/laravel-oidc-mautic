<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Tests\Claims;

use MauticPlugin\LaravelOidcBundle\Claims\RoleMapping;
use PHPUnit\Framework\TestCase;

final class RoleMappingTest extends TestCase
{
    public function test_it_maps_the_first_matching_claim_value(): void
    {
        $mapping = RoleMapping::fromLines(['Super Admin => 1', 'Support=>2', 'broken line', 'Editor => abc']);

        self::assertSame(2, $mapping->roleIdFor(['roles' => ['Support']], 'roles'));
        self::assertSame(1, $mapping->roleIdFor(['roles' => ['Support', 'Super Admin']], 'roles'));
        self::assertSame(1, $mapping->roleIdFor(['roles' => 'Super Admin'], 'roles'));
        self::assertNull($mapping->roleIdFor(['roles' => ['Editor']], 'roles'));
        self::assertNull($mapping->roleIdFor(['roles' => ['Support']], null));
        self::assertNull($mapping->roleIdFor([], 'roles'));
    }

    public function test_empty_mapping_never_matches(): void
    {
        self::assertNull(RoleMapping::fromLines([])->roleIdFor(['roles' => ['Support']], 'roles'));
    }
}
