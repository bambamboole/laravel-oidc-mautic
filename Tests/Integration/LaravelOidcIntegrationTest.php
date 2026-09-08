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
use MauticPlugin\LaravelOidcBundle\Tests\Support\TestIdp;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;

final class LaravelOidcIntegrationTest extends TestCase
{
    private TestIdp $idp;

    private MockHandler $http;

    private RequestStack $requestStack;

    private Role $defaultRole;

    private UserProvider&MockObject $userProvider;

    /** @var EntityRepository<Role>&MockObject */
    private EntityRepository&MockObject $roleRepository;

    protected function setUp(): void
    {
        $this->idp = TestIdp::make();
        $this->http = new MockHandler([
            new Response(200, [], json_encode($this->idp->discoveryDocument(), JSON_THROW_ON_ERROR)),
            new Response(200, [], json_encode($this->idp->jwksDocument(), JSON_THROW_ON_ERROR)),
        ]);
        $this->requestStack = new RequestStack;
        $this->defaultRole = new Role;
        $this->userProvider = $this->createMock(UserProvider::class);
        $this->roleRepository = $this->createMock(EntityRepository::class);
    }

    public function test_it_creates_a_user_from_userinfo_claims_with_the_default_role(): void
    {
        $this->userProvider->method('loadUserByIdentifier')->willThrowException(new UserNotFoundException);
        $this->queueUserinfo(['sub' => 'user-1', 'email' => 'jane@example.com', 'given_name' => 'Jane', 'family_name' => 'Doe']);

        $user = $this->integration([])->getUser($this->tokenResponse());

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
        $this->queueUserinfo(['sub' => 'user-1', 'email' => 'jane@example.com', 'given_name' => 'Jane', 'family_name' => 'Doe']);

        $user = $this->integration([])->getUser($this->tokenResponse());

        self::assertSame($existing, $user);
        self::assertSame('Jane', $user->getFirstName());
        self::assertSame($existingRole, $user->getRole());
    }

    public function test_it_rejects_users_whose_claims_miss_a_requirement(): void
    {
        $this->queueUserinfo(['sub' => 'user-1', 'email' => 'jane@example.com', 'roles' => ['Support'], 'email_verified' => true]);

        try {
            $this->integration(['oidc_required_claims' => ['roles=Super Admin', 'email_verified']])->getUser($this->tokenResponse());
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
        $this->queueUserinfo(['sub' => 'user-1', 'email' => 'jane@example.com', 'name' => 'Jane Doe', 'roles' => ['Super Admin']]);

        $user = $this->integration([
            'oidc_role_claim' => 'roles',
            'oidc_role_mapping' => ['Super Admin => 7'],
        ])->getUser($this->tokenResponse());

        self::assertSame($mappedRole, $user->getRole());
    }

    public function test_it_rejects_a_token_response_without_an_access_token(): void
    {
        $this->expectException(AuthenticationServiceException::class);
        $this->expectExceptionMessage('no access token');

        $this->integration([])->getUser(['token_type' => 'Bearer', 'id_token' => $this->idp->idToken()]);
    }

    public function test_it_rejects_a_token_response_without_an_id_token(): void
    {
        $this->expectException(AuthenticationServiceException::class);
        $this->expectExceptionMessage('no ID token');

        $this->integration([])->getUser(['token_type' => 'Bearer', 'access_token' => 'access-token']);
    }

    public function test_it_rejects_an_id_token_issued_for_another_client_before_calling_userinfo(): void
    {
        $integration = $this->integration([]);

        try {
            $integration->getUser($this->tokenResponse($this->idp->idToken(clientId: 'someone-else')));
            self::fail('Expected the ID token audience check to reject the login.');
        } catch (AuthenticationException $exception) {
            self::assertStringContainsString('not intended for this client', $exception->getMessage());
            self::assertSame('https://idp.test/.well-known/jwks.json', (string) $this->http->getLastRequest()?->getUri());
        }
    }

    public function test_it_rejects_userinfo_describing_another_subject_than_the_id_token(): void
    {
        $this->queueUserinfo(['sub' => 'someone-else', 'email' => 'mallory@example.com']);

        $this->expectException(AuthenticationServiceException::class);
        $this->expectExceptionMessage('another subject');

        $this->integration([])->getUser($this->tokenResponse($this->idp->idToken(['sub' => 'user-1'])));
    }

    public function test_it_verifies_the_nonce_stored_for_the_login_against_the_id_token(): void
    {
        $session = $this->startSession();
        $session->set('LaravelOidc_nonce', 'expected-nonce');
        $this->userProvider->method('loadUserByIdentifier')->willThrowException(new UserNotFoundException);
        $this->queueUserinfo(['sub' => 'user-1', 'email' => 'jane@example.com', 'name' => 'Jane Doe']);

        $user = $this->integration([])->getUser($this->tokenResponse($this->idp->idToken(nonce: 'expected-nonce')));

        self::assertSame('jane@example.com', $user->getUserIdentifier());
        self::assertFalse($session->has('LaravelOidc_nonce'), 'The nonce must be consumed once matched.');
    }

    public function test_it_rejects_an_id_token_whose_nonce_differs_from_the_login(): void
    {
        $this->startSession()->set('LaravelOidc_nonce', 'expected-nonce');

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('nonce');

        $this->integration([])->getUser($this->tokenResponse($this->idp->idToken(nonce: 'replayed-nonce')));
    }

    public function test_the_login_url_carries_pkce_nonce_and_the_configured_scopes(): void
    {
        $session = $this->startSession();
        $integration = $this->integration(['oidc_scopes' => 'openid email roles']);

        $url = $integration->getAuthLoginUrl();

        self::assertStringStartsWith('https://idp.test/oauth/authorize?client_id=client-id&response_type=code', $url);
        self::assertStringContainsString('&scope=openid+email+roles', $url);
        self::assertMatchesRegularExpression('/&code_challenge=[A-Za-z0-9_-]{43}&code_challenge_method=S256&nonce=[A-Za-z0-9_-]{43}$/', $url);

        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        self::assertSame($query['nonce'], $session->get('LaravelOidc_nonce'));
        self::assertSame($query['state'], $session->get('LaravelOidc_csrf_token'));
        self::assertIsString($session->get('LaravelOidc_pkce_verifier'));
    }

    public function test_the_callback_consumes_the_state_and_hands_the_pkce_verifier_to_the_token_request(): void
    {
        $session = $this->startSession(['state' => 'expected-state', 'code' => 'auth-code']);
        $session->set('LaravelOidc_csrf_token', 'expected-state');
        $session->set('LaravelOidc_pkce_verifier', 'the-verifier');
        $session->set('LaravelOidc_nonce', 'expected-nonce');
        $this->userProvider->method('loadUserByIdentifier')->willThrowException(new UserNotFoundException);
        $this->queueUserinfo(['sub' => 'user-1', 'email' => 'jane@example.com', 'name' => 'Jane Doe']);

        $integration = $this->integration([]);
        $integration->expects(self::once())->method('authCallback')
            ->with([], ['code_verifier' => 'the-verifier'])
            ->willReturn($this->tokenResponse($this->idp->idToken(nonce: 'expected-nonce')));

        $user = $integration->ssoAuthCallback();

        self::assertInstanceOf(User::class, $user);
        self::assertSame('jane@example.com', $user->getUserIdentifier());
        self::assertFalse($session->has('LaravelOidc_csrf_token'));
        self::assertFalse($session->has('LaravelOidc_pkce_verifier'));
    }

    public function test_the_callback_rejects_a_state_that_does_not_match_the_login(): void
    {
        $session = $this->startSession(['state' => 'forged-state', 'code' => 'auth-code']);
        $session->set('LaravelOidc_csrf_token', 'expected-state');
        $integration = $this->integration([]);
        $integration->expects(self::never())->method('authCallback');

        try {
            $integration->ssoAuthCallback();
            self::fail('Expected the state check to reject the callback.');
        } catch (AuthenticationException $exception) {
            self::assertSame('plugin.laraveloidc.error.invalid_state', $exception->getMessage());
            self::assertFalse($session->has('LaravelOidc_csrf_token'), 'A rejected state must not be retried.');
        }
    }

    public function test_the_callback_rejects_a_session_that_started_no_login(): void
    {
        $this->startSession(['state' => 'some-state', 'code' => 'auth-code']);
        $integration = $this->integration([]);
        $integration->expects(self::never())->method('authCallback');

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('invalid_state');

        $integration->ssoAuthCallback();
    }

    public function test_the_callback_rejects_a_request_without_a_session(): void
    {
        $this->requestStack->push(Request::create('/s/sso_login_check/LaravelOidc', 'GET', ['state' => 'some-state']));
        $integration = $this->integration([]);
        $integration->expects(self::never())->method('authCallback');

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('invalid_state');

        $integration->ssoAuthCallback();
    }

    /**
     * @return array<string, string>
     */
    private function tokenResponse(?string $idToken = null): array
    {
        return ['token_type' => 'Bearer', 'access_token' => 'access-token', 'id_token' => $idToken ?? $this->idp->idToken()];
    }

    /**
     * @param  array<string, string>  $query
     */
    private function startSession(array $query = []): Session
    {
        $session = new Session(new MockArraySessionStorage);
        $request = Request::create('/s/sso_login_check/LaravelOidc', 'GET', $query);
        $request->setSession($session);
        $this->requestStack->push($request);

        return $session;
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
    private function integration(array $parameters): LaravelOidcIntegration&MockObject
    {
        $integration = $this->getMockBuilder(LaravelOidcIntegration::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['getDecryptedApiKeys', 'getAuthCallbackUrl', 'authCallback'])
            ->getMock();
        $integration->method('getDecryptedApiKeys')->willReturn(['issuer' => 'https://idp.test', 'client_id' => 'client-id', 'client_secret' => 'secret']);
        $integration->method('getAuthCallbackUrl')->willReturn('https://mautic.test/s/sso_login_check/LaravelOidc');

        $settings = $this->createMock(Integration::class);
        $settings->method('getFeatureSettings')->willReturn(['new_user_role' => 3]);
        $integration->setIntegrationSettings($settings);

        $entityManager = $this->createMock(EntityManager::class);
        $entityManager->method('getReference')->with(Role::class, 3)->willReturn($this->defaultRole);
        $entityManager->method('getRepository')->with(Role::class)->willReturn($this->roleRepository);

        foreach (['em' => $entityManager, 'cache' => null, 'requestStack' => $this->requestStack] as $property => $value) {
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
