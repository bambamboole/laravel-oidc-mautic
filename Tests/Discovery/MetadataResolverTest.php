<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Tests\Discovery;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Mautic\CoreBundle\Helper\CacheStorageHelper;
use MauticPlugin\LaravelOidcBundle\Discovery\MetadataResolver;
use PHPUnit\Framework\TestCase;

final class MetadataResolverTest extends TestCase
{
    /** @var array<string, mixed> */
    private const DOCUMENT = [
        'issuer' => 'https://idp.test',
        'authorization_endpoint' => 'https://idp.test/oauth/authorize',
        'token_endpoint' => 'https://idp.test/oauth/token',
        'userinfo_endpoint' => 'https://idp.test/oauth/userinfo',
        'jwks_uri' => 'https://idp.test/.well-known/jwks.json',
    ];

    public function test_it_reads_endpoints_from_the_discovery_document(): void
    {
        $mock = new MockHandler([new Response(200, [], json_encode(self::DOCUMENT, JSON_THROW_ON_ERROR))]);

        $metadata = (new MetadataResolver(new Client(['handler' => HandlerStack::create($mock)])))->resolve('https://idp.test/');

        self::assertSame('https://idp.test/oauth/authorize', $metadata->authorizationEndpoint);
        self::assertSame('https://idp.test/oauth/token', $metadata->tokenEndpoint);
        self::assertSame('https://idp.test/oauth/userinfo', $metadata->userinfoEndpoint);
        self::assertSame('https://idp.test/.well-known/openid-configuration', (string) $mock->getLastRequest()?->getUri());
    }

    public function test_it_serves_a_cached_document_without_a_request(): void
    {
        $cache = $this->createMock(CacheStorageHelper::class);
        $cache->method('get')->willReturn(self::DOCUMENT);

        $mock = new MockHandler([]);

        $metadata = (new MetadataResolver(new Client(['handler' => HandlerStack::create($mock)]), $cache))->resolve('https://idp.test');

        self::assertSame('https://idp.test/oauth/token', $metadata->tokenEndpoint);
        self::assertNull($mock->getLastRequest());
    }

    public function test_it_caches_a_fresh_document(): void
    {
        $cache = $this->createMock(CacheStorageHelper::class);
        $cache->method('get')->willReturn(false);
        $cache->expects(self::once())->method('set')->with(self::stringStartsWith('oidc_metadata_'), self::DOCUMENT, 3600);

        $mock = new MockHandler([new Response(200, [], json_encode(self::DOCUMENT, JSON_THROW_ON_ERROR))]);

        (new MetadataResolver(new Client(['handler' => HandlerStack::create($mock)]), $cache))->resolve('https://idp.test');
    }

    public function test_it_rejects_a_document_without_endpoints(): void
    {
        $mock = new MockHandler([new Response(200, [], json_encode(['issuer' => 'https://idp.test'], JSON_THROW_ON_ERROR))]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('authorization_endpoint');

        (new MetadataResolver(new Client(['handler' => HandlerStack::create($mock)])))->resolve('https://idp.test');
    }
}
