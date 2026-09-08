<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Tests\Security;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Mautic\CoreBundle\Helper\CacheStorageHelper;
use MauticPlugin\LaravelOidcBundle\Security\JwksKeySet;
use MauticPlugin\LaravelOidcBundle\Tests\Support\BuildsInMemoryCache;
use MauticPlugin\LaravelOidcBundle\Tests\Support\TestIdp;
use PHPUnit\Framework\TestCase;

final class JwksKeySetTest extends TestCase
{
    use BuildsInMemoryCache;

    public function test_it_builds_a_pem_that_verifies_the_idp_signature(): void
    {
        $idp = TestIdp::make();
        $keySet = $this->keySet($idp);

        $pems = $keySet->pemKeysFor('https://idp.test/.well-known/jwks.json');

        self::assertArrayHasKey($idp->kid, $pems);

        $token = $idp->accessToken();
        [$header, $claims] = explode('.', $token, 3);
        $signature = $this->signatureOf($token);

        self::assertSame(1, openssl_verify($header.'.'.$claims, $signature, $pems[$idp->kid], OPENSSL_ALGO_SHA256));
    }

    public function test_it_serves_cached_keys_without_a_request(): void
    {
        $idp = TestIdp::make();
        $cache = $this->createMock(CacheStorageHelper::class);
        $cache->method('get')->willReturn(['cached-kid' => 'cached-pem']);

        $mock = new MockHandler([]);
        $keySet = new JwksKeySet(new Client(['handler' => HandlerStack::create($mock)]), $cache);

        self::assertSame(['cached-kid' => 'cached-pem'], $keySet->pemKeysFor('https://idp.test/.well-known/jwks.json'));
        self::assertNull($mock->getLastRequest());
    }

    public function test_a_refresh_bypasses_the_cache_and_replaces_it(): void
    {
        $idp = TestIdp::make();
        $store = ['oidc_jwks_'.md5('https://idp.test/.well-known/jwks.json') => ['stale-kid' => 'stale-pem']];
        $mock = new MockHandler([new Response(200, [], json_encode($idp->jwksDocument(), JSON_THROW_ON_ERROR))]);
        $keySet = new JwksKeySet(new Client(['handler' => HandlerStack::create($mock)]), $this->inMemoryCache($store));

        $pems = $keySet->refreshedPemKeysFor('https://idp.test/.well-known/jwks.json');

        self::assertIsArray($pems);
        self::assertArrayHasKey($idp->kid, $pems);
        self::assertSame($pems, $store['oidc_jwks_'.md5('https://idp.test/.well-known/jwks.json')]);
        self::assertSame($pems, $keySet->pemKeysFor('https://idp.test/.well-known/jwks.json'));
    }

    public function test_a_refresh_is_not_repeated_within_the_cooldown(): void
    {
        $idp = TestIdp::make();
        $store = [];
        $mock = new MockHandler([new Response(200, [], json_encode($idp->jwksDocument(), JSON_THROW_ON_ERROR))]);
        $keySet = new JwksKeySet(new Client(['handler' => HandlerStack::create($mock)]), $this->inMemoryCache($store));

        self::assertIsArray($keySet->refreshedPemKeysFor('https://idp.test/.well-known/jwks.json'));
        self::assertNull($keySet->refreshedPemKeysFor('https://idp.test/.well-known/jwks.json'));
        self::assertCount(0, $mock);
    }

    public function test_there_is_nothing_to_refresh_without_a_cache(): void
    {
        $mock = new MockHandler([]);
        $keySet = new JwksKeySet(new Client(['handler' => HandlerStack::create($mock)]));

        self::assertNull($keySet->refreshedPemKeysFor('https://idp.test/.well-known/jwks.json'));
        self::assertNull($mock->getLastRequest());
    }

    public function test_it_rejects_a_document_without_usable_keys(): void
    {
        $mock = new MockHandler([
            new Response(200, [], json_encode(['keys' => [['kty' => 'EC', 'kid' => 'ec-key']]], JSON_THROW_ON_ERROR)),
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('no usable RSA signing key');

        (new JwksKeySet(new Client(['handler' => HandlerStack::create($mock)])))
            ->pemKeysFor('https://idp.test/.well-known/jwks.json');
    }

    private function keySet(TestIdp $idp): JwksKeySet
    {
        $mock = new MockHandler([
            new Response(200, [], json_encode($idp->jwksDocument(), JSON_THROW_ON_ERROR)),
        ]);

        return new JwksKeySet(new Client(['handler' => HandlerStack::create($mock)]));
    }

    private function signatureOf(string $jwt): string
    {
        $encoded = explode('.', $jwt)[2];
        $decoded = base64_decode(strtr($encoded, '-_', '+/'), true);

        self::assertIsString($decoded);

        return $decoded;
    }
}
