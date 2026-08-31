<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Security;

use GuzzleHttp\ClientInterface;
use Mautic\CoreBundle\Helper\CacheStorageHelper;

final class JwksKeySet
{
    private const CACHE_TTL_SECONDS = 3600;

    public function __construct(
        private readonly ClientInterface $httpClient,
        private readonly ?CacheStorageHelper $cache = null,
    ) {}

    /**
     * @return array<string, string> signing key PEMs keyed by kid
     */
    public function pemKeysFor(string $jwksUri): array
    {
        $cacheKey = 'oidc_jwks_'.md5($jwksUri);

        $cached = $this->cache?->get($cacheKey, self::CACHE_TTL_SECONDS);

        if (is_array($cached) && $cached !== []) {
            /** @var array<string, string> $cached */
            return $cached;
        }

        $body = $this->httpClient
            ->request('GET', $jwksUri, ['http_errors' => true])
            ->getBody()
            ->getContents();

        $document = json_decode($body, true, 512, JSON_THROW_ON_ERROR);

        if (! is_array($document) || ! is_array($document['keys'] ?? null)) {
            throw new \RuntimeException('The JWKS document must contain a "keys" list.');
        }

        $pems = [];

        foreach ($document['keys'] as $key) {
            if (! is_array($key) || ($key['kty'] ?? null) !== 'RSA' || ($key['use'] ?? 'sig') !== 'sig') {
                continue;
            }

            $kid = $key['kid'] ?? null;
            $modulus = $key['n'] ?? null;
            $exponent = $key['e'] ?? null;

            if (! is_string($kid) || ! is_string($modulus) || ! is_string($exponent)) {
                continue;
            }

            $pems[$kid] = self::pemFromModulusAndExponent($modulus, $exponent);
        }

        if ($pems === []) {
            throw new \RuntimeException('The JWKS document contains no usable RSA signing key.');
        }

        $this->cache?->set($cacheKey, $pems, self::CACHE_TTL_SECONDS);

        return $pems;
    }

    /**
     * Builds a SubjectPublicKeyInfo PEM from the JWK's base64url modulus and
     * exponent, since Mautic's vendor tree ships no JOSE library to do it.
     */
    private static function pemFromModulusAndExponent(string $modulus, string $exponent): string
    {
        $modulusBytes = self::base64UrlDecode($modulus);
        $exponentBytes = self::base64UrlDecode($exponent);

        // A leading 1-bit would flip the ASN.1 INTEGER negative; pad with a zero octet.
        if ($modulusBytes !== '' && (ord($modulusBytes[0]) & 0x80) !== 0) {
            $modulusBytes = "\x00".$modulusBytes;
        }

        $rsaPublicKey = self::derSequence(
            self::derInteger($modulusBytes).self::derInteger($exponentBytes),
        );

        $rsaOidWithNullParams = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
        $subjectPublicKeyInfo = self::derSequence(
            $rsaOidWithNullParams.self::derBitString($rsaPublicKey),
        );

        return "-----BEGIN PUBLIC KEY-----\n"
            .chunk_split(base64_encode($subjectPublicKeyInfo), 64, "\n")
            .'-----END PUBLIC KEY-----';
    }

    private static function base64UrlDecode(string $value): string
    {
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);

        if ($decoded === false) {
            throw new \RuntimeException('The JWK contains invalid base64url data.');
        }

        return $decoded;
    }

    /**
     * @param  int<0, max>  $length
     */
    private static function derLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $bytes = ltrim(pack('N', $length), "\x00");

        return chr(0x80 | min(strlen($bytes), 0x7F)).$bytes;
    }

    private static function derInteger(string $bytes): string
    {
        return "\x02".self::derLength(strlen($bytes)).$bytes;
    }

    private static function derSequence(string $bytes): string
    {
        return "\x30".self::derLength(strlen($bytes)).$bytes;
    }

    private static function derBitString(string $bytes): string
    {
        return "\x03".self::derLength(strlen($bytes) + 1)."\x00".$bytes;
    }
}
