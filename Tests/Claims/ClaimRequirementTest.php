<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Tests\Claims;

use MauticPlugin\LaravelOidcBundle\Claims\ClaimRequirement;
use MauticPlugin\LaravelOidcBundle\Claims\ClaimRequirements;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ClaimRequirementTest extends TestCase
{
    /**
     * @return iterable<string, array{string, array<string, mixed>, bool}>
     */
    public static function requirements(): iterable
    {
        yield 'scalar equals' => ['hd=example.com', ['hd' => 'example.com'], true];
        yield 'scalar differs' => ['hd=example.com', ['hd' => 'other.com'], false];
        yield 'list contains value' => ['roles=Super Admin', ['roles' => ['Support', 'Super Admin']], true];
        yield 'list without value' => ['roles=Super Admin', ['roles' => ['Support']], false];
        yield 'bare claim requires true' => ['email_verified', ['email_verified' => true], true];
        yield 'bare claim rejects false' => ['email_verified', ['email_verified' => false], false];
        yield 'boolean spelled out' => ['email_verified=true', ['email_verified' => true], true];
        yield 'nested path' => ['tenant.slug=acme', ['tenant' => ['slug' => 'acme']], true];
        yield 'missing claim' => ['roles=Super Admin', [], false];
        yield 'object claim never matches' => ['tenant=acme', ['tenant' => ['slug' => 'acme']], false];
        yield 'surrounding whitespace is ignored' => ['  roles = Super Admin ', ['roles' => ['Super Admin']], true];
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    #[DataProvider('requirements')]
    public function test_it_matches_claims(string $line, array $claims, bool $expected): void
    {
        $requirement = ClaimRequirement::fromLine($line);

        self::assertNotNull($requirement);
        self::assertSame($expected, $requirement->isSatisfiedBy($claims));
    }

    public function test_blank_and_comment_lines_are_skipped(): void
    {
        self::assertNull(ClaimRequirement::fromLine(''));
        self::assertNull(ClaimRequirement::fromLine('   '));
        self::assertNull(ClaimRequirement::fromLine('# roles=Super Admin'));
        self::assertNull(ClaimRequirement::fromLine('=value'));
    }

    public function test_all_requirements_must_hold(): void
    {
        $requirements = ClaimRequirements::fromLines(['roles=Super Admin', 'email_verified', '', 42]);

        self::assertSame([], $requirements->unmetBy(['roles' => ['Super Admin'], 'email_verified' => true]));

        $unmet = $requirements->unmetBy(['roles' => ['Support'], 'email_verified' => true]);

        self::assertCount(1, $unmet);
        self::assertSame('roles=Super Admin', $unmet[0]->describe());
    }

    public function test_no_requirements_allow_everyone(): void
    {
        $requirements = ClaimRequirements::fromLines([]);

        self::assertTrue($requirements->isEmpty());
        self::assertSame([], $requirements->unmetBy([]));
    }
}
