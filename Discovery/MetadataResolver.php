<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Discovery;

use GuzzleHttp\ClientInterface;
use Mautic\CoreBundle\Helper\CacheStorageHelper;

final class MetadataResolver
{
    private const CACHE_TTL_SECONDS = 3600;

    public function __construct(
        private readonly ClientInterface $httpClient,
        private readonly ?CacheStorageHelper $cache = null,
    ) {}

    public function resolve(string $issuer): ProviderMetadata
    {
        $issuer = rtrim(trim($issuer), '/');
        self::assertHttps($issuer);
        // v2: cached v1 documents predate jwks_uri and would fail hydration.
        $cacheKey = 'oidc_metadata_v2_'.md5($issuer);

        $cached = $this->cache?->get($cacheKey, self::CACHE_TTL_SECONDS);

        if (is_array($cached)) {
            /** @var array<string, mixed> $cached */
            return ProviderMetadata::fromDiscoveryDocument($cached);
        }

        $body = $this->httpClient
            ->request('GET', $issuer.'/.well-known/openid-configuration', ['http_errors' => true])
            ->getBody()
            ->getContents();

        $document = json_decode($body, true, 512, JSON_THROW_ON_ERROR);

        if (! is_array($document)) {
            throw new \RuntimeException('The OpenID Connect discovery document must be a JSON object.');
        }

        /** @var array<string, mixed> $document */
        $metadata = ProviderMetadata::fromDiscoveryDocument($document);

        // OpenID Connect Discovery 4.3: the document must describe the issuer it was fetched from.
        if (rtrim($metadata->issuer, '/') !== $issuer) {
            throw new \RuntimeException(sprintf('The discovery document names the issuer "%s" instead of the configured "%s".', $metadata->issuer, $issuer));
        }

        $this->cache?->set($cacheKey, $metadata->toArray(), self::CACHE_TTL_SECONDS);

        return $metadata;
    }

    /**
     * OpenID Connect Core requires an https issuer. Plain http is tolerated on
     * loopback hosts only, so a provider can be developed against locally.
     */
    private static function assertHttps(string $issuer): void
    {
        $scheme = strtolower((string) parse_url($issuer, PHP_URL_SCHEME));
        $host = strtolower((string) parse_url($issuer, PHP_URL_HOST));

        if ($scheme === 'https' || ($scheme === 'http' && in_array($host, ['localhost', '127.0.0.1', '[::1]'], true))) {
            return;
        }

        throw new \RuntimeException('The OpenID Connect issuer must be an https:// URL.');
    }
}
