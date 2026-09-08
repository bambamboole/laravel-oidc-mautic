<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Security;

use MauticPlugin\LaravelOidcBundle\Discovery\ProviderMetadata;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * The checks every JWT from the provider must pass, regardless of whether it
 * is an ID token or an access token: an RS256 signature by a key from the
 * provider's JWKS, the configured issuer, and a plausible lifetime.
 */
final class JwtVerifier
{
    private const CLOCK_LEEWAY_SECONDS = 60;

    public function __construct(private readonly JwksKeySet $keySet) {}

    /**
     * Only RS256 is accepted — pinning the algorithm to what the JWKS can
     * prove defuses alg-substitution tokens. Token-type specific checks such
     * as audience, client, or nonce are left to the caller.
     *
     * @return array<string, mixed> the verified claims
     *
     * @throws AuthenticationException when the token is not valid
     */
    public function verify(string $token, ProviderMetadata $metadata): array
    {
        $segments = explode('.', $token);

        if (count($segments) !== 3) {
            throw new AuthenticationException('The token is not a JWT.');
        }

        [$encodedHeader, $encodedClaims, $encodedSignature] = $segments;

        $header = $this->decodeSegment($encodedHeader);

        if (($header['alg'] ?? null) !== 'RS256') {
            throw new AuthenticationException('The token must be signed with RS256.');
        }

        $kid = $header['kid'] ?? null;

        if (! is_string($kid) || $kid === '') {
            throw new AuthenticationException('The token names no signing key.');
        }

        $pem = $this->signingKey($metadata->jwksUri, $kid);
        $signature = base64_decode(strtr($encodedSignature, '-_', '+/'), true);

        if ($signature === false || openssl_verify($encodedHeader.'.'.$encodedClaims, $signature, $pem, OPENSSL_ALGO_SHA256) !== 1) {
            throw new AuthenticationException('The token signature is invalid.');
        }

        $claims = $this->decodeSegment($encodedClaims);

        if (($claims['iss'] ?? null) !== $metadata->issuer) {
            throw new AuthenticationException('The token was not issued by the configured provider.');
        }

        $this->assertTimely($claims);

        return $claims;
    }

    /**
     * The `aud` claim as a list, whether the provider sent a string or an array.
     *
     * @param  array<string, mixed>  $claims
     * @return list<string>
     */
    public static function audienceOf(array $claims): array
    {
        $audience = $claims['aud'] ?? [];

        return array_values(array_filter(is_array($audience) ? $audience : [$audience], is_string(...)));
    }

    private function signingKey(string $jwksUri, string $kid): string
    {
        $pem = $this->keySet->pemKeysFor($jwksUri)[$kid] ?? null;

        // An unknown kid usually means the provider rotated keys since the JWKS was cached.
        $pem ??= $this->keySet->refreshedPemKeysFor($jwksUri)[$kid] ?? null;

        return $pem ?? throw new AuthenticationException('The token is signed with an unknown key.');
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function assertTimely(array $claims): void
    {
        $now = time();
        $expiry = $claims['exp'] ?? null;

        if (! is_numeric($expiry) || (int) $expiry < $now - self::CLOCK_LEEWAY_SECONDS) {
            throw new AuthenticationException('The token is expired.');
        }

        $notBefore = $claims['nbf'] ?? null;

        if (is_numeric($notBefore) && (int) $notBefore > $now + self::CLOCK_LEEWAY_SECONDS) {
            throw new AuthenticationException('The token is not yet valid.');
        }

        $issuedAt = $claims['iat'] ?? null;

        if ($issuedAt !== null && (! is_numeric($issuedAt) || (int) $issuedAt > $now + self::CLOCK_LEEWAY_SECONDS)) {
            throw new AuthenticationException('The token claims to be issued in the future.');
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeSegment(string $segment): array
    {
        $decoded = base64_decode(strtr($segment, '-_', '+/'), true);
        $data = $decoded === false ? null : json_decode($decoded, true);

        if (! is_array($data)) {
            throw new AuthenticationException('The token is malformed.');
        }

        /** @var array<string, mixed> $data */
        return $data;
    }
}
