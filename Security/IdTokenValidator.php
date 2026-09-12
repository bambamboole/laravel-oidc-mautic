<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Security;

use MauticPlugin\LaravelOidcBundle\Discovery\ProviderMetadata;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

final class IdTokenValidator
{
    private readonly JwtVerifier $verifier;

    public function __construct(JwksKeySet $keySet)
    {
        $this->verifier = new JwtVerifier($keySet);
    }

    /**
     * OpenID Connect Core 3.1.3.7. The returned claims carry a non-empty `sub`.
     *
     * @param  string|null  $expectedNonce  the nonce sent with the authorization request, or null when none was sent
     * @return array<string, mixed>
     *
     * @throws AuthenticationException when the ID token is not valid
     */
    public function validate(string $idToken, ProviderMetadata $metadata, string $clientId, ?string $expectedNonce): array
    {
        $claims = $this->verifier->verify($idToken, $metadata);

        if (! is_string($claims['sub'] ?? null) || $claims['sub'] === '') {
            throw new AuthenticationException('The ID token names no subject.');
        }

        if (! is_numeric($claims['iat'] ?? null)) {
            throw new AuthenticationException('The ID token has no issue time.');
        }

        if (! in_array($clientId, JwtVerifier::audienceOf($claims), true)) {
            throw new AuthenticationException('The ID token is not intended for this client.');
        }

        $authorizedParty = $claims['azp'] ?? null;

        if ($authorizedParty !== null && $authorizedParty !== $clientId) {
            throw new AuthenticationException('The ID token was authorized for another party.');
        }

        if ($expectedNonce !== null) {
            $nonce = $claims['nonce'] ?? null;

            if (! is_string($nonce) || ! hash_equals($expectedNonce, $nonce)) {
                throw new AuthenticationException('The ID token nonce does not match the login request.');
            }
        }

        return $claims;
    }
}
