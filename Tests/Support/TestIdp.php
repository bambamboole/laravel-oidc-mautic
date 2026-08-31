<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Tests\Support;

/**
 * A miniature identity provider for tests: one RSA keypair, its JWKS document,
 * and RS256-signed access tokens over arbitrary claims.
 */
final class TestIdp
{
    private function __construct(
        private readonly \OpenSSLAsymmetricKey $privateKey,
        public readonly string $kid,
        public readonly string $issuer,
    ) {}

    public static function make(string $issuer = 'https://idp.test', string $kid = 'test-key'): self
    {
        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($key === false) {
            throw new \RuntimeException('Could not generate an RSA keypair: '.openssl_error_string());
        }

        return new self($key, $kid, $issuer);
    }

    /**
     * @return array<string, mixed>
     */
    public function discoveryDocument(): array
    {
        return [
            'issuer' => $this->issuer,
            'authorization_endpoint' => $this->issuer.'/oauth/authorize',
            'token_endpoint' => $this->issuer.'/oauth/token',
            'userinfo_endpoint' => $this->issuer.'/oauth/userinfo',
            'jwks_uri' => $this->issuer.'/.well-known/jwks.json',
        ];
    }

    /**
     * @return array{keys: list<array<string, string>>}
     */
    public function jwksDocument(): array
    {
        $details = openssl_pkey_get_details($this->privateKey);

        if ($details === false || ! isset($details['rsa']['n'], $details['rsa']['e'])) {
            throw new \RuntimeException('Could not read RSA key details.');
        }

        return ['keys' => [[
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => $this->kid,
            'n' => self::base64UrlEncode($details['rsa']['n']),
            'e' => self::base64UrlEncode($details['rsa']['e']),
        ]]];
    }

    /**
     * @param  array<string, mixed>  $claims  merged over sane defaults (iss, exp, client_id)
     */
    public function accessToken(array $claims = [], ?string $kid = null, string $alg = 'RS256'): string
    {
        $header = ['typ' => 'at+jwt', 'alg' => $alg, 'kid' => $kid ?? $this->kid];
        $claims = array_merge([
            'iss' => $this->issuer,
            'exp' => time() + 300,
            'client_id' => 'test-client',
        ], $claims);

        $payload = self::base64UrlEncode(json_encode($header, JSON_THROW_ON_ERROR))
            .'.'
            .self::base64UrlEncode(json_encode($claims, JSON_THROW_ON_ERROR));

        openssl_sign($payload, $signature, $this->privateKey, OPENSSL_ALGO_SHA256);

        return $payload.'.'.self::base64UrlEncode($signature);
    }

    public function tokenWithBrokenSignature(): string
    {
        $token = $this->accessToken();

        return substr($token, 0, -6).'AAAAAA';
    }

    private static function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
