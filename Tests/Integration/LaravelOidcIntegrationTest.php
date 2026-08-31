<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Tests\Integration;

use Doctrine\ORM\EntityManager;
use Doctrine\ORM\EntityRepository;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Mautic\CoreBundle\Helper\CoreParametersHelper;
use Mautic\PluginBundle\Entity\Integration;
use Mautic\PluginBundle\Integration\AbstractIntegration;
use Mautic\UserBundle\Entity\Role;
use Mautic\UserBundle\Entity\User;
use Mautic\UserBundle\Security\Provider\UserProvider;
use MauticPlugin\LaravelOidcBundle\Integration\LaravelOidcIntegration;
use MauticPlugin\LaravelOidcBundle\Security\ClaimsNotSatisfiedException;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;

final class LaravelOidcIntegrationTest extends TestCase
{
    private const DISCOVERY = [
        'issuer' => 'https://idp.test',
        'authorization_endpoint' => 'https://idp.test/oauth/authorize',
        'token_endpoint' => 'https://idp.test/oauth/token',
        'userinfo_endpoint' => 'https://idp.test/oauth/userinfo',
        'jwks_uri' => 'https://idp.test/.well-known/jwks.json',
    ];

    private const TOKEN = ['token_type' => 'Bearer', 'access_token' => 'access-token'];

    private MockHandler $http;

    private Role $defaultRole;

    private UserProvider&MockObject $userProvider;

    /** @var EntityRepository<Role>&MockObject */
    private EntityRepository&MockObject $roleRepository;

    protected function setUp(): void
    {
        $this->http = new MockHandler([new Response(200, [], json_encode(self::DISCOVERY, JSON_THROW_ON_ERROR))]);
        $this->defaultRole = new Role;
        $this->userProvider = $this->createMock(UserProvider::class);
        $this->roleRepository = $this->createMock(EntityRepository::class);
    }

    public function test_it_creates_a_user_from_userinfo_claims_with_the_default_role(): void
    {
        $this->userProvider->method('loadUserByIdentifier')->willThrowException(new UserNotFoundException);
        $this->queueUserinfo(['sub' => '1', 'email' => 'jane@example.com', 'given_name' => 'Jane', 'family_name' => 'Doe']);

        $user = $this->integration([])->getUser(self::TOKEN);

        self::assertSame('jane@example.com', $user->getUserIdentifier());
        self::assertSame('Jane', $user->getFirstName());
        self::assertSame($this->defaultRole, $user->getRole());

        $request = $this->http->getLastRequest();
        self::assertNotNull($request);
        self::assertSame('https://idp.test/oauth/userinfo', (string) $request->getUri());
        self::assertSame('Bearer access-token', $request->getHeaderLine('Authorization'));
    }

    public function test_it_updates_an_existing_user_and_keeps_its_role(): void
    {
        $existingRole = new Role;
        $existing = (new User)->setUsername('jane@example.com')->setFirstName('Old')->setLastName('Name')->setRole($existingRole);
        $this->userProvider->method('loadUserByIdentifier')->with('jane@example.com')->willReturn($existing);
        $this->queueUserinfo(['sub' => '1', 'email' => 'jane@example.com', 'given_name' => 'Jane', 'family_name' => 'Doe']);

        $user = $this->integration([])->getUser(self::TOKEN);

        self::assertSame($existing, $user);
        self::assertSame('Jane', $user->getFirstName());
        self::assertSame($existingRole, $user->getRole());
    }

    public function test_it_rejects_users_whose_claims_miss_a_requirement(): void
    {
        $this->queueUserinfo(['sub' => '1', 'email' => 'jane@example.com', 'roles' => ['Support'], 'email_verified' => true]);

        try {
            $this->integration(['oidc_required_claims' => ['roles=Super Admin', 'email_verified']])->getUser(self::TOKEN);
            self::fail('Expected the claim restriction to reject the login.');
        } catch (ClaimsNotSatisfiedException $exception) {
            self::assertSame(['%claims%' => 'roles=Super Admin'], $exception->getMessageData());
        }
    }

    public function test_it_assigns_a_mapped_role_from_the_role_claim(): void
    {
        $mappedRole = new Role;
        $this->roleRepository->method('find')->with(7)->willReturn($mappedRole);
        $this->userProvider->method('loadUserByIdentifier')->willThrowException(new UserNotFoundException);
        $this->queueUserinfo(['sub' => '1', 'email' => 'jane@example.com', 'name' => 'Jane Doe', 'roles' => ['Super Admin']]);

        $user = $this->integration([
            'oidc_role_claim' => 'roles',
            'oidc_role_mapping' => ['Super Admin => 7'],
        ])->getUser(self::TOKEN);

        self::assertSame($mappedRole, $user->getRole());
    }

    public function test_it_rejects_a_token_response_without_an_access_token(): void
    {
        $this->expectException(AuthenticationServiceException::class);

        $this->integration([])->getUser(['token_type' => 'Bearer']);
    }

    public function test_the_login_url_carries_a_pkce_challenge_and_the_configured_scopes(): void
    {
        $integration = $this->integration(['oidc_scopes' => 'openid email roles']);

        $url = $integration->getAuthLoginUrl();

        self::assertStringStartsWith('https://idp.test/oauth/authorize?client_id=client-id&response_type=code', $url);
        self::assertStringContainsString('&scope=openid+email+roles', $url);
        self::assertMatchesRegularExpression('/&code_challenge=[A-Za-z0-9_-]{43}&code_challenge_method=S256$/', $url);
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function queueUserinfo(array $claims): void
    {
        $this->http->append(new Response(200, [], json_encode($claims, JSON_THROW_ON_ERROR)));
    }

    /**
     * @param  array<string, mixed>  $parameters
     */
    private function integration(array $parameters): LaravelOidcIntegration
    {
        $integration = $this->getMockBuilder(LaravelOidcIntegration::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['getDecryptedApiKeys', 'getAuthCallbackUrl'])
            ->getMock();
        $integration->method('getDecryptedApiKeys')->willReturn(['issuer' => 'https://idp.test', 'client_id' => 'client-id', 'client_secret' => 'secret']);
        $integration->method('getAuthCallbackUrl')->willReturn('https://mautic.test/s/sso_login_check/LaravelOidc');

        $settings = $this->createMock(Integration::class);
        $settings->method('getFeatureSettings')->willReturn(['new_user_role' => 3]);
        $integration->setIntegrationSettings($settings);

        $entityManager = $this->createMock(EntityManager::class);
        $entityManager->method('getReference')->with(Role::class, 3)->willReturn($this->defaultRole);
        $entityManager->method('getRepository')->with(Role::class)->willReturn($this->roleRepository);

        $requestStack = new RequestStack;

        foreach (['em' => $entityManager, 'cache' => null, 'requestStack' => $requestStack] as $property => $value) {
            $reflection = new \ReflectionProperty(AbstractIntegration::class, $property);
            $reflection->setValue($integration, $value);
        }

        $helper = $this->createMock(CoreParametersHelper::class);
        $helper->method('get')->willReturnCallback(static fn (string $key): mixed => $parameters[$key] ?? null);

        $integration->setHttpClient(new Client(['handler' => HandlerStack::create($this->http)]));
        $integration->setCoreParametersHelper($helper);
        $integration->setUserProvider($this->userProvider);

        return $integration;
    }
}
