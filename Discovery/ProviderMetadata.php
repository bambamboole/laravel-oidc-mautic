<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Discovery;

final readonly class ProviderMetadata
{
    public function __construct(
        public string $issuer,
        public string $authorizationEndpoint,
        public string $tokenEndpoint,
        public string $userinfoEndpoint,
        public string $jwksUri,
    ) {}

    /**
     * @param  array<string, mixed>  $document
     */
    public static function fromDiscoveryDocument(array $document): self
    {
        $endpoints = [];

        foreach (['issuer', 'authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri'] as $key) {
            $value = $document[$key] ?? null;

            if (! is_string($value) || $value === '') {
                throw new \RuntimeException(sprintf('The OpenID Connect discovery document is missing "%s".', $key));
            }

            $endpoints[$key] = $value;
        }

        return new self(
            $endpoints['issuer'],
            $endpoints['authorization_endpoint'],
            $endpoints['token_endpoint'],
            $endpoints['userinfo_endpoint'],
            $endpoints['jwks_uri'],
        );
    }

    /**
     * @return array<string, string>
     */
    public function toArray(): array
    {
        return [
            'issuer' => $this->issuer,
            'authorization_endpoint' => $this->authorizationEndpoint,
            'token_endpoint' => $this->tokenEndpoint,
            'userinfo_endpoint' => $this->userinfoEndpoint,
            'jwks_uri' => $this->jwksUri,
        ];
    }
}
