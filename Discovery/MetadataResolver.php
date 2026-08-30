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
        $cacheKey = 'oidc_metadata_'.md5($issuer);

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

        $this->cache?->set($cacheKey, $metadata->toArray(), self::CACHE_TTL_SECONDS);

        return $metadata;
    }
}
