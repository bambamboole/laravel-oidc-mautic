<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Claims;

final readonly class ClaimRequirements
{
    /**
     * @param  list<ClaimRequirement>  $requirements
     */
    private function __construct(private array $requirements) {}

    /**
     * @param  iterable<mixed>  $lines
     */
    public static function fromLines(iterable $lines): self
    {
        $requirements = [];

        foreach ($lines as $line) {
            if (! is_string($line)) {
                continue;
            }

            $requirement = ClaimRequirement::fromLine($line);

            if ($requirement !== null) {
                $requirements[] = $requirement;
            }
        }

        return new self($requirements);
    }

    /**
     * @param  array<string, mixed>  $claims
     * @return list<ClaimRequirement>
     */
    public function unmetBy(array $claims): array
    {
        return array_values(array_filter(
            $this->requirements,
            static fn (ClaimRequirement $requirement): bool => ! $requirement->isSatisfiedBy($claims),
        ));
    }

    public function isEmpty(): bool
    {
        return $this->requirements === [];
    }
}
