<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Tests\Support;

use Mautic\CoreBundle\Helper\CacheStorageHelper;
use PHPUnit\Framework\MockObject\MockObject;

trait BuildsInMemoryCache
{
    /**
     * A CacheStorageHelper double backed by the given array, which the test
     * keeps a reference to for seeding and inspection.
     *
     * @param  array<string, mixed>  $store
     */
    private function inMemoryCache(array &$store): CacheStorageHelper&MockObject
    {
        $cache = $this->createMock(CacheStorageHelper::class);
        $cache->method('get')->willReturnCallback(static function (string $name) use (&$store): mixed {
            return $store[$name] ?? false;
        });
        $cache->method('set')->willReturnCallback(static function (string $name, mixed $data) use (&$store): void {
            $store[$name] = $data;
        });

        return $cache;
    }
}
