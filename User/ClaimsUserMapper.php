<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\User;

use Mautic\CoreBundle\Helper\CoreParametersHelper;
use Mautic\UserBundle\Entity\User;
use MauticPlugin\LaravelOidcBundle\Claims\ClaimPath;

final class ClaimsUserMapper
{
    public function __construct(private readonly CoreParametersHelper $parameters) {}

    /**
     * @param  array<string, mixed>  $claims
     */
    public function username(array $claims): string
    {
        return ClaimPath::readString($claims, $this->claimPath('oidc_username_claim', 'email'));
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    public function apply(User $user, array $claims): User
    {
        $username = $this->username($claims);
        [$firstName, $lastName] = $this->names($claims, $username);

        $user
            ->setUsername($username)
            ->setEmail(ClaimPath::readString($claims, $this->claimPath('oidc_email_claim', 'email')))
            ->setFirstName($firstName)
            ->setLastName($lastName);

        $timezone = ClaimPath::readString($claims, $this->claimPath('oidc_timezone_claim', 'zoneinfo'));
        $locale = ClaimPath::readString($claims, $this->claimPath('oidc_locale_claim', 'locale'));

        if ($timezone !== '') {
            $user->setTimezone($timezone);
        }

        if ($locale !== '') {
            $user->setLocale($locale);
        }

        return $user;
    }

    /**
     * Falls back to the `name` claim, then the username, because Mautic refuses users without both names.
     *
     * @param  array<string, mixed>  $claims
     * @return array{string, string}
     */
    private function names(array $claims, string $username): array
    {
        $firstName = ClaimPath::readString($claims, $this->claimPath('oidc_first_name_claim', 'given_name'));
        $lastName = ClaimPath::readString($claims, $this->claimPath('oidc_last_name_claim', 'family_name'));

        if ($firstName !== '' && $lastName !== '') {
            return [$firstName, $lastName];
        }

        $fullName = ClaimPath::readString($claims, 'name');
        $localPart = strstr($username, '@', true);
        $fallback = $fullName !== '' ? $fullName : ($localPart !== false && $localPart !== '' ? $localPart : $username);
        $parts = preg_split('/\s+/', $fallback, 2) ?: [$fallback];

        return [
            $firstName !== '' ? $firstName : $parts[0],
            $lastName !== '' ? $lastName : ($parts[1] ?? $parts[0]),
        ];
    }

    private function claimPath(string $parameter, ?string $default = null): ?string
    {
        $configured = $this->parameters->get($parameter);

        if (is_string($configured) && trim($configured) !== '') {
            return $configured;
        }

        return $default;
    }
}
