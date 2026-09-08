<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Tests\Security;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use MauticPlugin\LaravelOidcBundle\Discovery\ProviderMetadata;
use MauticPlugin\LaravelOidcBundle\Security\IdTokenValidator;
use MauticPlugin\LaravelOidcBundle\Security\JwksKeySet;
use MauticPlugin\LaravelOidcBundle\Tests\Support\TestIdp;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

final class IdTokenValidatorTest extends TestCase
{
    private TestIdp $idp;

    protected function setUp(): void
    {
        $this->idp = TestIdp::make();
    }

    public function test_it_returns_the_claims_of_a_valid_id_token(): void
    {
        $token = $this->idp->idToken(['sub' => 'jane', 'email' => 'jane@example.com'], nonce: 'n-1');

        $claims = $this->validator()->validate($token, $this->metadata(), 'client-id', 'n-1');

        self::assertSame('jane', $claims['sub']);
        self::assertSame('jane@example.com', $claims['email']);
    }

    public function test_it_accepts_a_list_audience_naming_this_client(): void
    {
        $token = $this->idp->idToken(['aud' => ['other', 'client-id'], 'azp' => 'client-id']);

        self::assertSame('user-1', $this->validator()->validate($token, $this->metadata(), 'client-id', null)['sub']);
    }

    public function test_it_rejects_a_token_for_another_client(): void
    {
        $token = $this->idp->idToken(clientId: 'someone-else');

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('not intended for this client');

        $this->validator()->validate($token, $this->metadata(), 'client-id', null);
    }

    public function test_it_rejects_a_token_authorized_for_another_party(): void
    {
        $token = $this->idp->idToken(['aud' => ['client-id', 'other'], 'azp' => 'other']);

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('another party');

        $this->validator()->validate($token, $this->metadata(), 'client-id', null);
    }

    public function test_it_rejects_a_nonce_that_does_not_match(): void
    {
        $token = $this->idp->idToken(nonce: 'replayed');

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('nonce');

        $this->validator()->validate($token, $this->metadata(), 'client-id', 'fresh');
    }

    public function test_it_rejects_a_missing_nonce_when_one_was_sent(): void
    {
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('nonce');

        $this->validator()->validate($this->idp->idToken(), $this->metadata(), 'client-id', 'fresh');
    }

    public function test_it_skips_the_nonce_when_none_was_sent(): void
    {
        $claims = $this->validator()->validate($this->idp->idToken(nonce: 'whatever'), $this->metadata(), 'client-id', null);

        self::assertSame('user-1', $claims['sub']);
    }

    public function test_it_rejects_a_token_without_a_subject(): void
    {
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('subject');

        $this->validator()->validate($this->idp->idToken(['sub' => '']), $this->metadata(), 'client-id', null);
    }

    public function test_it_rejects_a_token_without_an_issue_time(): void
    {
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('issue time');

        $this->validator()->validate($this->idp->idToken(['iat' => null]), $this->metadata(), 'client-id', null);
    }

    public function test_it_rejects_a_token_issued_in_the_future(): void
    {
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('future');

        $this->validator()->validate($this->idp->idToken(['iat' => time() + 600]), $this->metadata(), 'client-id', null);
    }

    public function test_it_rejects_a_broken_signature(): void
    {
        $token = $this->idp->idToken();
        $tampered = substr($token, 0, -6).'AAAAAA';

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('signature');

        $this->validator()->validate($tampered, $this->metadata(), 'client-id', null);
    }

    public function test_it_rejects_a_foreign_issuer(): void
    {
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('not issued by');

        $this->validator()->validate($this->idp->idToken(['iss' => 'https://evil.test']), $this->metadata(), 'client-id', null);
    }

    private function validator(): IdTokenValidator
    {
        $mock = new MockHandler([
            new Response(200, [], json_encode($this->idp->jwksDocument(), JSON_THROW_ON_ERROR)),
        ]);

        return new IdTokenValidator(new JwksKeySet(new Client(['handler' => HandlerStack::create($mock)])));
    }

    private function metadata(): ProviderMetadata
    {
        return ProviderMetadata::fromDiscoveryDocument($this->idp->discoveryDocument());
    }
}
