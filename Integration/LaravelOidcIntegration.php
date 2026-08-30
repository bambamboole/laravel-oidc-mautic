<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Integration;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use Mautic\CoreBundle\Helper\CoreParametersHelper;
use Mautic\PluginBundle\Integration\AbstractSsoServiceIntegration;
use Mautic\UserBundle\Entity\Role;
use Mautic\UserBundle\Entity\User;
use Mautic\UserBundle\Security\Provider\UserProvider;
use MauticPlugin\LaravelOidcBundle\Claims\ClaimRequirements;
use MauticPlugin\LaravelOidcBundle\Claims\RoleMapping;
use MauticPlugin\LaravelOidcBundle\Discovery\MetadataResolver;
use MauticPlugin\LaravelOidcBundle\Discovery\ProviderMetadata;
use MauticPlugin\LaravelOidcBundle\Security\ClaimsNotSatisfiedException;
use MauticPlugin\LaravelOidcBundle\User\ClaimsUserMapper;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;

class LaravelOidcIntegration extends AbstractSsoServiceIntegration
{
    public const NAME = 'LaravelOidc';

    private const SESSION_PKCE_VERIFIER = self::NAME.'_pkce_verifier';

    private ?ClientInterface $httpClient = null;

    private ?CoreParametersHelper $coreParametersHelper = null;

    private ?UserProvider $userProvider = null;

    private ?ProviderMetadata $metadata = null;

    public function getName(): string
    {
        return self::NAME;
    }

    public function getDisplayName(): string
    {
        return 'OpenID Connect';
    }

    public function getIcon(): string
    {
        return 'plugins/LaravelOidcBundle/Assets/img/openid.svg';
    }

    public function getAuthenticationType(): string
    {
        return 'oauth2';
    }

    /**
     * @return array<string, string>
     */
    public function getRequiredKeyFields(): array
    {
        return [
            'issuer' => 'plugin.laraveloidc.keyfield.issuer',
            'client_id' => 'plugin.laraveloidc.keyfield.client_id',
            'client_secret' => 'plugin.laraveloidc.keyfield.client_secret',
        ];
    }

    public function getAuthenticationUrl(): string
    {
        return $this->metadata()->authorizationEndpoint;
    }

    public function getAccessTokenUrl(): string
    {
        return $this->metadata()->tokenEndpoint;
    }

    public function getAuthScope(): string
    {
        $scopes = $this->coreParametersHelper?->get('oidc_scopes');

        return is_string($scopes) && trim($scopes) !== '' ? trim($scopes) : 'openid profile email';
    }

    public function getAuthLoginUrl(): string
    {
        $verifier = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        if ($this->requestStack->getCurrentRequest()?->hasSession()) {
            $this->requestStack->getSession()->set(self::SESSION_PKCE_VERIFIER, $verifier);
        }

        return parent::getAuthLoginUrl().'&code_challenge='.$challenge.'&code_challenge_method=S256';
    }

    /**
     * @param  array<string, mixed>  $settings
     * @param  array<string, mixed>  $parameters
     * @return User|mixed
     */
    public function ssoAuthCallback($settings = [], $parameters = []): mixed
    {
        if ($this->requestStack->getCurrentRequest()?->hasSession()) {
            $session = $this->requestStack->getSession();
            $verifier = $session->get(self::SESSION_PKCE_VERIFIER);
            $session->remove(self::SESSION_PKCE_VERIFIER);

            if (is_string($verifier) && $verifier !== '') {
                $parameters['code_verifier'] = $verifier;
            }
        }

        return parent::ssoAuthCallback($settings, $parameters);
    }

    public function setCoreParametersHelper(CoreParametersHelper $coreParametersHelper): void
    {
        $this->coreParametersHelper = $coreParametersHelper;
    }

    public function setUserProvider(UserProvider $userProvider): void
    {
        $this->userProvider = $userProvider;
    }

    public function setHttpClient(ClientInterface $httpClient): void
    {
        $this->httpClient = $httpClient;
    }

    /**
     * @param  mixed  $response  The parsed token endpoint response
     *
     * @throws AuthenticationException when the provider's claims do not satisfy the configured requirements
     */
    public function getUser($response): User
    {
        if (! is_array($response) || ! is_string($response['access_token'] ?? null)) {
            throw new AuthenticationServiceException('The OpenID Connect token response has no access token.');
        }

        $claims = $this->fetchUserinfo($response['access_token']);

        $unmet = $this->claimRequirements()->unmetBy($claims);

        if ($unmet !== []) {
            throw new ClaimsNotSatisfiedException($unmet);
        }

        $mapper = new ClaimsUserMapper($this->parametersHelper());
        $user = $this->findExistingUser($mapper->username($claims));
        $isNew = $user === null;
        $user = $mapper->apply($user ?? new User, $claims);

        $mappedRole = $this->mappedRole($claims);

        if ($mappedRole !== null) {
            $user->setRole($mappedRole);
        } elseif ($isNew) {
            $user->setRole($this->defaultRoleForNewUsers());
        }

        return $user;
    }

    /**
     * @return array<string, mixed>
     */
    private function fetchUserinfo(string $accessToken): array
    {
        $body = $this->httpClient()->request('GET', $this->metadata()->userinfoEndpoint, [
            'headers' => ['Authorization' => 'Bearer '.$accessToken, 'Accept' => 'application/json'],
            'http_errors' => true,
        ])->getBody()->getContents();

        $claims = json_decode($body, true, 512, JSON_THROW_ON_ERROR);

        if (! is_array($claims)) {
            throw new AuthenticationServiceException('The userinfo response must be a JSON object.');
        }

        /** @var array<string, mixed> $claims */
        return $claims;
    }

    private function claimRequirements(): ClaimRequirements
    {
        $lines = $this->parametersHelper()->get('oidc_required_claims');

        return ClaimRequirements::fromLines(is_array($lines) ? $lines : []);
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function mappedRole(array $claims): ?Role
    {
        $lines = $this->parametersHelper()->get('oidc_role_mapping');
        $claimPath = $this->parametersHelper()->get('oidc_role_claim');

        $roleId = RoleMapping::fromLines(is_array($lines) ? $lines : [])
            ->roleIdFor($claims, is_string($claimPath) ? $claimPath : null);

        if ($roleId === null) {
            return null;
        }

        $role = $this->em->getRepository(Role::class)->find($roleId);

        return $role instanceof Role ? $role : null;
    }

    private function defaultRoleForNewUsers(): Role
    {
        $role = $this->getUserRole();

        if (! $role instanceof Role) {
            throw new AuthenticationException('mautic.integration.sso.error.no_role');
        }

        return $role;
    }

    private function findExistingUser(string $username): ?User
    {
        if ($username === '') {
            return null;
        }

        try {
            return $this->userProvider()->loadUserByIdentifier($username);
        } catch (AuthenticationException) {
            return null;
        }
    }

    private function metadata(): ProviderMetadata
    {
        if ($this->metadata !== null) {
            return $this->metadata;
        }

        $issuer = $this->keys['issuer'] ?? null;

        if (! is_string($issuer) || trim($issuer) === '') {
            throw new \RuntimeException('The OpenID Connect issuer is not configured.');
        }

        return $this->metadata = (new MetadataResolver($this->httpClient(), $this->cache))->resolve($issuer);
    }

    private function httpClient(): ClientInterface
    {
        return $this->httpClient ??= new Client;
    }

    private function parametersHelper(): CoreParametersHelper
    {
        return $this->coreParametersHelper ?? throw new \LogicException('CoreParametersHelper must be set before authenticating.');
    }

    private function userProvider(): UserProvider
    {
        return $this->userProvider ?? throw new \LogicException('UserProvider must be set before authenticating.');
    }
}
