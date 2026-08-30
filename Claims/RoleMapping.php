<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Claims;

final readonly class RoleMapping
{
    /**
     * @param  array<string, int>  $roleIdsByClaimValue
     */
    private function __construct(private array $roleIdsByClaimValue) {}

    /**
     * Lines of `claim value => mautic role id`.
     *
     * @param  iterable<mixed>  $lines
     */
    public static function fromLines(iterable $lines): self
    {
        $mapping = [];

        foreach ($lines as $line) {
            if (! is_string($line) || ! str_contains($line, '=>')) {
                continue;
            }

            [$claimValue, $roleId] = array_map('trim', explode('=>', $line, 2));

            if ($claimValue === '' || ! ctype_digit($roleId)) {
                continue;
            }

            $mapping[$claimValue] = (int) $roleId;
        }

        return new self($mapping);
    }

    /**
     * The first mapped role id whose claim value is present; null when nothing matches.
     *
     * @param  array<string, mixed>  $claims
     */
    public function roleIdFor(array $claims, ?string $claimPath): ?int
    {
        if ($this->roleIdsByClaimValue === [] || $claimPath === null || trim($claimPath) === '') {
            return null;
        }

        $value = ClaimPath::read($claims, $claimPath);
        $values = is_array($value) ? $value : [$value];

        foreach ($this->roleIdsByClaimValue as $claimValue => $roleId) {
            foreach ($values as $candidate) {
                if (is_scalar($candidate) && (string) $candidate === (string) $claimValue) {
                    return $roleId;
                }
            }
        }

        return null;
    }
}
