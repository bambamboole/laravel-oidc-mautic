<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Security;

use MauticPlugin\LaravelOidcBundle\Claims\ClaimRequirement;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

final class ClaimsNotSatisfiedException extends AuthenticationException
{
    private const string MESSAGE_KEY = 'plugin.laraveloidc.error.claims_not_satisfied';

    /** @var list<ClaimRequirement> */
    private array $unmet;

    /**
     * @param  list<ClaimRequirement>  $unmet
     */
    public function __construct(array $unmet)
    {
        $this->unmet = $unmet;

        parent::__construct(self::MESSAGE_KEY);
    }

    public function getMessageKey(): string
    {
        return self::MESSAGE_KEY;
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

    /**
     * AuthenticationException::__serialize() carries only the token, code,
     * message, file and line, and tells subclasses holding more to override the
     * pair. Mautic stashes the failure in the session for the login page to
     * render, so without this the requirements are gone by the time the page
     * asks for them.
     *
     * @return array{list<ClaimRequirement>, array<array-key, mixed>}
     */
    public function __serialize(): array
    {
        return [$this->unmet, parent::__serialize()];
    }

    /**
     * @param  array{list<ClaimRequirement>, array<array-key, mixed>}  $data
     */
    public function __unserialize(array $data): void
    {
        [$this->unmet, $parent] = $data;

        parent::__unserialize($parent);
    }
}
