<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Security;

use FOS\OAuthServerBundle\Model\AccessTokenManagerInterface;
use FOS\OAuthServerBundle\Model\AuthCodeManagerInterface;
use FOS\OAuthServerBundle\Model\ClientManagerInterface;
use FOS\OAuthServerBundle\Model\RefreshTokenManagerInterface;
use FOS\OAuthServerBundle\Model\TokenInterface;
use FOS\OAuthServerBundle\Storage\OAuthStorage;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\ClientInterface;
use Mautic\ApiBundle\Entity\oAuth2\AccessToken;
use Mautic\ApiBundle\Entity\oAuth2\Client;
use Mautic\CoreBundle\Helper\CacheStorageHelper;
use Mautic\CoreBundle\Helper\CoreParametersHelper;
use Mautic\PluginBundle\Helper\IntegrationHelper;
use MauticPlugin\LaravelOidcBundle\Claims\ClaimPath;
use MauticPlugin\LaravelOidcBundle\Discovery\MetadataResolver;
use MauticPlugin\LaravelOidcBundle\Integration\LaravelOidcIntegration;
use Symfony\Component\PasswordHasher\Hasher\PasswordHasherFactoryInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * Decorates the OAuth storage so a standard `Authorization: Bearer` access
 * token issued by the OpenID Connect provider authenticates against the API.
 * Locally stored Mautic OAuth tokens keep taking precedence; only when the
 * lookup misses and the bearer token is a JWT from the configured issuer is a
 * transient access token synthesized. It acts as the Mautic user named by the
 * configured user claim when the token carries one, and otherwise as the
 * shared API user.
 */
class OidcBearerTokenStorage extends OAuthStorage
{
    /**
     * @param  UserProviderInterface<UserInterface>|null  $userProvider
     */
    public function __construct(
        ClientManagerInterface $clientManager,
        AccessTokenManagerInterface $accessTokenManager,
        RefreshTokenManagerInterface $refreshTokenManager,
        AuthCodeManagerInterface $authCodeManager,
        ?UserProviderInterface $userProvider,
        ?PasswordHasherFactoryInterface $passwordHasherFactory,
        private readonly CoreParametersHelper $coreParametersHelper,
        private readonly IntegrationHelper $integrationHelper,
        private readonly ?CacheStorageHelper $cacheStorageHelper = null,
        private ?ClientInterface $httpClient = null,
    ) {
        parent::__construct($clientManager, $accessTokenManager, $refreshTokenManager, $authCodeManager, $userProvider, $passwordHasherFactory);
    }

    public function getAccessToken($token): ?TokenInterface
    {
        return parent::getAccessToken($token) ?? $this->accessTokenFromProviderJwt((string) $token);
    }

    private function accessTokenFromProviderJwt(string $token): ?TokenInterface
    {
        $apiUserEmail = $this->trimmedParameter('oidc_api_user_email');
        $userClaim = $this->trimmedParameter('oidc_api_user_claim');
        $allowedClientIds = $this->coreParametersHelper->get('oidc_api_allowed_client_ids');
        $allowedClientIds = array_values(array_filter(is_array($allowedClientIds) ? $allowedClientIds : [], is_string(...)));

        if (($apiUserEmail === null && $userClaim === null) || $allowedClientIds === [] || substr_count($token, '.') !== 2) {
            return null;
        }

        $issuer = $this->issuer();
        $userProvider = $this->userProvider;

        if ($issuer === null || $userProvider === null) {
            return null;
        }

        $audience = $this->trimmedParameter('oidc_api_audience');

        try {
            $httpClient = $this->httpClient ??= new HttpClient;
            $metadata = (new MetadataResolver($httpClient, $this->cacheStorageHelper))->resolve($issuer);
            $claims = (new ApiTokenValidator(new JwksKeySet($httpClient, $this->cacheStorageHelper)))
                ->validate($token, $metadata, $allowedClientIds, $audience);
            $user = $userProvider->loadUserByIdentifier($this->userIdentifierFor($claims, $userClaim, $apiUserEmail));
        } catch (AuthenticationException) {
            return null;
        }

        return $this->synthesizeAccessToken($token, $user, $claims);
    }

    /**
     * A token carrying the configured user claim acts as that person, so API
     * calls are audited under their own account; a token without it — such as
     * one from a client_credentials grant — falls back to the shared API user.
     *
     * @param  array<string, mixed>  $claims
     */
    private function userIdentifierFor(array $claims, ?string $userClaim, ?string $apiUserEmail): string
    {
        $identifier = $userClaim === null ? '' : ClaimPath::readString($claims, $userClaim);

        if ($identifier !== '') {
            return $identifier;
        }

        return $apiUserEmail ?? throw new AuthenticationException('The API token names no user and no shared API user is configured.');
    }

    private function trimmedParameter(string $name): ?string
    {
        $value = $this->coreParametersHelper->get($name);

        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function synthesizeAccessToken(string $token, UserInterface $user, array $claims): AccessToken
    {
        // The authenticator builds its passport user from the client's user
        // identifier, so the synthetic client must identify as the API user.
        $client = new Client;
        $client->setRandomId($user->getUserIdentifier());

        $accessToken = new AccessToken;
        $accessToken->setToken($token);
        $accessToken->setUser($user);
        $accessToken->setClient($client);
        $expiry = $claims['exp'] ?? null;
        $accessToken->setExpiresAt(is_numeric($expiry) ? (int) $expiry : null);

        return $accessToken;
    }

    private function issuer(): ?string
    {
        $integration = $this->integrationHelper->getIntegrationObject(LaravelOidcIntegration::NAME);

        if (! $integration instanceof LaravelOidcIntegration) {
            return null;
        }

        $issuer = $integration->getDecryptedApiKeys()['issuer'] ?? null;

        return is_string($issuer) && trim($issuer) !== '' ? trim($issuer) : null;
    }
}
