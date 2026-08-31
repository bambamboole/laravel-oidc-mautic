<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Security;

use MauticPlugin\LaravelOidcBundle\Discovery\ProviderMetadata;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

final class ApiTokenValidator
{
    private const CLOCK_LEEWAY_SECONDS = 60;

    public function __construct(private readonly JwksKeySet $keySet) {}

    /**
     * Validates an RFC 9068 access token issued by the configured provider and
     * returns its claims. Only RS256 is accepted — pinning the algorithm to
     * what the JWKS can prove defuses alg-substitution tokens. When an
     * expected audience is given, the token's `aud` claim must contain it.
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

        $segments = explode('.', $token);

        if (count($segments) !== 3) {
            throw new AuthenticationException('The API token is not a JWT.');
        }

        [$encodedHeader, $encodedClaims, $encodedSignature] = $segments;

        $header = $this->decodeSegment($encodedHeader);

        if (($header['alg'] ?? null) !== 'RS256') {
            throw new AuthenticationException('The API token must be signed with RS256.');
        }

        $kid = $header['kid'] ?? null;

        if (! is_string($kid) || $kid === '') {
            throw new AuthenticationException('The API token names no signing key.');
        }

        $pem = $this->keySet->pemKeysFor($metadata->jwksUri)[$kid] ?? null;

        if ($pem === null) {
            throw new AuthenticationException('The API token is signed with an unknown key.');
        }

        $signature = base64_decode(strtr($encodedSignature, '-_', '+/'), true);

        if ($signature === false || openssl_verify($encodedHeader.'.'.$encodedClaims, $signature, $pem, OPENSSL_ALGO_SHA256) !== 1) {
            throw new AuthenticationException('The API token signature is invalid.');
        }

        $claims = $this->decodeSegment($encodedClaims);

        if (($claims['iss'] ?? null) !== $metadata->issuer) {
            throw new AuthenticationException('The API token was not issued by the configured provider.');
        }

        $now = time();
        $expiry = $claims['exp'] ?? null;

        if (! is_numeric($expiry) || (int) $expiry < $now - self::CLOCK_LEEWAY_SECONDS) {
            throw new AuthenticationException('The API token is expired.');
        }

        $notBefore = $claims['nbf'] ?? null;

        if (is_numeric($notBefore) && (int) $notBefore > $now + self::CLOCK_LEEWAY_SECONDS) {
            throw new AuthenticationException('The API token is not yet valid.');
        }

        $clientId = $claims['client_id'] ?? null;

        if (! is_string($clientId) || ! in_array($clientId, $allowedClientIds, true)) {
            throw new AuthenticationException('The API token client is not allowed.');
        }

        if ($expectedAudience !== null && $expectedAudience !== '') {
            $audience = $claims['aud'] ?? [];
            $audience = array_filter(is_array($audience) ? $audience : [$audience], is_string(...));

            if (! in_array($expectedAudience, $audience, true)) {
                throw new AuthenticationException('The API token is not intended for this audience.');
            }
        }

        return $claims;
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeSegment(string $segment): array
    {
        $decoded = base64_decode(strtr($segment, '-_', '+/'), true);
        $data = $decoded === false ? null : json_decode($decoded, true);

        if (! is_array($data)) {
            throw new AuthenticationException('The API token is malformed.');
        }

        /** @var array<string, mixed> $data */
        return $data;
    }
}
