<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Claims;

final class ClaimPath
{
    /**
     * @param  array<string, mixed>  $claims
     */
    public static function read(array $claims, string $path): mixed
    {
        $value = $claims;

        foreach (explode('.', trim($path)) as $segment) {
            if (! is_array($value) || ! array_key_exists($segment, $value)) {
                return null;
            }

            $value = $value[$segment];
        }

        return $value;
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    public static function readString(array $claims, ?string $path): string
    {
        if ($path === null || trim($path) === '') {
            return '';
        }

        $value = self::read($claims, $path);

        return is_scalar($value) ? trim((string) $value) : '';
    }
}
