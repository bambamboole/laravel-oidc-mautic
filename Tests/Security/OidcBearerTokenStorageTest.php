<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Tests\Security;

use FOS\OAuthServerBundle\Model\AccessTokenManagerInterface;
use FOS\OAuthServerBundle\Model\AuthCodeManagerInterface;
use FOS\OAuthServerBundle\Model\ClientManagerInterface;
use FOS\OAuthServerBundle\Model\RefreshTokenManagerInterface;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Mautic\ApiBundle\Entity\oAuth2\AccessToken;
use Mautic\CoreBundle\Helper\CoreParametersHelper;
use Mautic\PluginBundle\Helper\IntegrationHelper;
use Mautic\UserBundle\Entity\User;
use MauticPlugin\LaravelOidcBundle\Integration\LaravelOidcIntegration;
use MauticPlugin\LaravelOidcBundle\Security\OidcBearerTokenStorage;
use MauticPlugin\LaravelOidcBundle\Tests\Support\TestIdp;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

final class OidcBearerTokenStorageTest extends TestCase
{
    private TestIdp $idp;

    private AccessTokenManagerInterface&MockObject $accessTokenManager;

    /** @var UserProviderInterface<UserInterface>&MockObject */
    private UserProviderInterface&MockObject $userProvider;

    private IntegrationHelper&MockObject $integrationHelper;

    private User $apiUser;

    protected function setUp(): void
    {
        $this->idp = TestIdp::make();
        $this->accessTokenManager = $this->createMock(AccessTokenManagerInterface::class);
        $this->userProvider = $this->createMock(UserProviderInterface::class);
        $this->integrationHelper = $this->createMock(IntegrationHelper::class);
        $this->apiUser = (new User)->setUsername('api@example.com');

        $integration = $this->createMock(LaravelOidcIntegration::class);
        $integration->method('getDecryptedApiKeys')->willReturn(['issuer' => $this->idp->issuer]);
        $this->integrationHelper->method('getIntegrationObject')->with(LaravelOidcIntegration::NAME)->willReturn($integration);
    }

    public function test_it_synthesizes_an_access_token_for_a_valid_provider_jwt(): void
    {
        $this->userProvider->method('loadUserByIdentifier')->with('api@example.com')->willReturn($this->apiUser);
        $jwt = $this->idp->accessToken(['client_id' => 'artisan-os']);

        $accessToken = $this->storage()->getAccessToken($jwt);

        self::assertInstanceOf(AccessToken::class, $accessToken);
        self::assertSame($this->apiUser, $accessToken->getUser());
        self::assertSame($jwt, $accessToken->getToken());
        self::assertFalse($accessToken->hasExpired());
        self::assertSame('api@example.com', $accessToken->getClient()->getUserIdentifier());
    }

    public function test_a_locally_stored_token_takes_precedence(): void
    {
        $stored = new AccessToken;
        $this->accessTokenManager->method('findTokenByToken')->willReturn($stored);
        $this->integrationHelper->expects(self::never())->method('getIntegrationObject');

        self::assertSame($stored, $this->storage()->getAccessToken('opaque-mautic-token'));
    }

    public function test_it_rejects_a_jwt_from_a_client_that_is_not_allowed(): void
    {
        $jwt = $this->idp->accessToken(['client_id' => 'stranger']);

        self::assertNull($this->storage()->getAccessToken($jwt));
    }

    public function test_it_rejects_a_tampered_jwt(): void
    {
        self::assertNull($this->storage()->getAccessToken($this->idp->tokenWithBrokenSignature()));
    }

    public function test_it_ignores_bearer_tokens_while_api_auth_is_not_configured(): void
    {
        $storage = $this->storage(parameters: [
            'oidc_api_user_email' => null,
            'oidc_api_allowed_client_ids' => [],
        ]);
        $this->integrationHelper->expects(self::never())->method('getIntegrationObject');

        self::assertNull($storage->getAccessToken($this->idp->accessToken(['client_id' => 'artisan-os'])));
    }

    public function test_it_enforces_the_configured_audience(): void
    {
        $parameters = [
            'oidc_api_user_email' => 'api@example.com',
            'oidc_api_allowed_client_ids' => ['artisan-os'],
            'oidc_api_audience' => 'https://mail.test',
        ];
        $this->userProvider->method('loadUserByIdentifier')->willReturn($this->apiUser);

        $bound = $this->idp->accessToken(['client_id' => 'artisan-os', 'aud' => ['https://mail.test']]);
        self::assertInstanceOf(AccessToken::class, $this->storage($parameters)->getAccessToken($bound));

        $unbound = $this->idp->accessToken(['client_id' => 'artisan-os']);
        self::assertNull($this->storage($parameters)->getAccessToken($unbound));
    }

    public function test_it_ignores_opaque_tokens_that_are_not_jwts(): void
    {
        $this->integrationHelper->expects(self::never())->method('getIntegrationObject');

        self::assertNull($this->storage()->getAccessToken('opaque-token'));
    }

    /**
     * @param  array<string, mixed>|null  $parameters
     */
    private function storage(?array $parameters = null): OidcBearerTokenStorage
    {
        $parameters ??= [
            'oidc_api_user_email' => 'api@example.com',
            'oidc_api_allowed_client_ids' => ['artisan-os'],
        ];

        $parametersHelper = $this->createMock(CoreParametersHelper::class);
        $parametersHelper->method('get')->willReturnCallback(
            static fn (string $name): mixed => $parameters[$name] ?? null,
        );

        $mock = new MockHandler([
            new Response(200, [], json_encode($this->idp->discoveryDocument(), JSON_THROW_ON_ERROR)),
            new Response(200, [], json_encode($this->idp->jwksDocument(), JSON_THROW_ON_ERROR)),
        ]);

        return new OidcBearerTokenStorage(
            $this->createMock(ClientManagerInterface::class),
            $this->accessTokenManager,
            $this->createMock(RefreshTokenManagerInterface::class),
            $this->createMock(AuthCodeManagerInterface::class),
            $this->userProvider,
            null,
            $parametersHelper,
            $this->integrationHelper,
            null,
            new Client(['handler' => HandlerStack::create($mock)]),
        );
    }
}
