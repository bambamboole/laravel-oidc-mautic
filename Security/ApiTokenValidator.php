<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Security;

use MauticPlugin\LaravelOidcBundle\Discovery\ProviderMetadata;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

final class ApiTokenValidator
{
    private readonly JwtVerifier $verifier;

    public function __construct(JwksKeySet $keySet)
    {
        $this->verifier = new JwtVerifier($keySet);
    }

    /**
     * Validates an RFC 9068 access token issued by the configured provider and
     * returns its claims. Beyond the signature, issuer, and lifetime checks the
     * token must name an allowed client and, when an expected audience is
     * given, its `aud` claim must contain it.
     *
     * @param  list<string>  $allowedClientIds
     * @return array<string, mixed>
     *
     * @throws AuthenticationException when the token is not valid
     */
    public function validate(string $token, ProviderMetadata $metadata, array $allowedClientIds, ?string $expectedAudience = null): array
    {
        if ($allowedClientIds === []) {
            throw new AuthenticationException('No API client is allowed.');
        }

        $claims = $this->verifier->verify($token, $metadata);

        $clientId = $claims['client_id'] ?? null;

        if (! is_string($clientId) || ! in_array($clientId, $allowedClientIds, true)) {
            throw new AuthenticationException('The API token client is not allowed.');
        }

        if ($expectedAudience !== null && $expectedAudience !== '' && ! in_array($expectedAudience, JwtVerifier::audienceOf($claims), true)) {
            throw new AuthenticationException('The API token is not intended for this audience.');
        }

        return $claims;
    }
}
