<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Security;

use MauticPlugin\LaravelOidcBundle\Claims\ClaimRequirement;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

final class ClaimsNotSatisfiedException extends AuthenticationException
{
    /**
     * @param  list<ClaimRequirement>  $unmet
     */
    public function __construct(private readonly array $unmet)
    {
        parent::__construct($this->getMessageKey());
    }

    public function getMessageKey(): string
    {
        return 'plugin.laraveloidc.error.claims_not_satisfied';
    }

    /**
     * @return array<string, string>
     */
    public function getMessageData(): array
    {
        return ['%claims%' => implode(', ', array_map(
            static fn (ClaimRequirement $requirement): string => $requirement->describe(),
            $this->unmet,
        ))];
    }
}
