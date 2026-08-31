<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Tests\Security;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use MauticPlugin\LaravelOidcBundle\Discovery\ProviderMetadata;
use MauticPlugin\LaravelOidcBundle\Security\ApiTokenValidator;
use MauticPlugin\LaravelOidcBundle\Security\JwksKeySet;
use MauticPlugin\LaravelOidcBundle\Tests\Support\TestIdp;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

final class ApiTokenValidatorTest extends TestCase
{
    private TestIdp $idp;

    protected function setUp(): void
    {
        $this->idp = TestIdp::make();
    }

    public function test_it_returns_the_claims_of_a_valid_token(): void
    {
        $token = $this->idp->accessToken(['client_id' => 'artisan-os', 'scope' => 'contacts']);

        $claims = $this->validator()->validate($token, $this->metadata(), ['artisan-os']);

        self::assertSame('artisan-os', $claims['client_id']);
        self::assertSame('contacts', $claims['scope']);
    }

    public function test_it_rejects_a_broken_signature(): void
    {
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('signature');

        $this->validator()->validate($this->idp->tokenWithBrokenSignature(), $this->metadata(), ['test-client']);
    }

    public function test_it_rejects_a_token_signed_by_another_key(): void
    {
        $stranger = TestIdp::make($this->idp->issuer, $this->idp->kid);

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('signature');

        $this->validator()->validate($stranger->accessToken(), $this->metadata(), ['test-client']);
    }

    public function test_it_rejects_an_expired_token(): void
    {
        $token = $this->idp->accessToken(['exp' => time() - 120]);

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('expired');

        $this->validator()->validate($token, $this->metadata(), ['test-client']);
    }

    public function test_it_rejects_a_foreign_issuer(): void
    {
        $token = $this->idp->accessToken(['iss' => 'https://evil.test']);

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('not issued by');

        $this->validator()->validate($token, $this->metadata(), ['test-client']);
    }

    public function test_it_rejects_a_client_that_is_not_allowed(): void
    {
        $token = $this->idp->accessToken(['client_id' => 'someone-else']);

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('client is not allowed');

        $this->validator()->validate($token, $this->metadata(), ['artisan-os']);
    }

    public function test_it_rejects_an_empty_allowlist(): void
    {
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('No API client');

        $this->validator()->validate($this->idp->accessToken(), $this->metadata(), []);
    }

    public function test_it_rejects_an_unknown_kid(): void
    {
        $token = $this->idp->accessToken(kid: 'rotated-away');

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('unknown key');

        $this->validator()->validate($token, $this->metadata(), ['test-client']);
    }

    public function test_it_pins_the_algorithm_to_rs256(): void
    {
        $token = $this->idp->accessToken(alg: 'none');

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('RS256');

        $this->validator()->validate($token, $this->metadata(), ['test-client']);
    }

    public function test_it_accepts_a_token_whose_audience_contains_the_expected_one(): void
    {
        $token = $this->idp->accessToken(['aud' => ['https://mail.test', 'other'], 'client_id' => 'test-client']);

        $claims = $this->validator()->validate($token, $this->metadata(), ['test-client'], 'https://mail.test');

        self::assertSame(['https://mail.test', 'other'], $claims['aud']);
    }

    public function test_it_accepts_a_string_audience_claim(): void
    {
        $token = $this->idp->accessToken(['aud' => 'https://mail.test']);

        $claims = $this->validator()->validate($token, $this->metadata(), ['test-client'], 'https://mail.test');

        self::assertSame('https://mail.test', $claims['aud']);
    }

    public function test_it_rejects_a_token_for_another_audience(): void
    {
        $token = $this->idp->accessToken(['aud' => ['https://somewhere-else.test']]);

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('audience');

        $this->validator()->validate($token, $this->metadata(), ['test-client'], 'https://mail.test');
    }

    public function test_it_rejects_a_token_without_audience_when_one_is_expected(): void
    {
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('audience');

        $this->validator()->validate($this->idp->accessToken(), $this->metadata(), ['test-client'], 'https://mail.test');
    }

    public function test_it_ignores_the_audience_while_none_is_configured(): void
    {
        $claims = $this->validator()->validate($this->idp->accessToken(), $this->metadata(), ['test-client'], null);

        self::assertSame('test-client', $claims['client_id']);
    }

    public function test_it_rejects_a_token_that_is_not_a_jwt(): void
    {
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('not a JWT');

        $this->validator()->validate('opaque-token', $this->metadata(), ['test-client']);
    }

    private function validator(): ApiTokenValidator
    {
        $mock = new MockHandler([
            new Response(200, [], json_encode($this->idp->jwksDocument(), JSON_THROW_ON_ERROR)),
        ]);

        return new ApiTokenValidator(new JwksKeySet(new Client(['handler' => HandlerStack::create($mock)])));
    }

    private function metadata(): ProviderMetadata
    {
        return ProviderMetadata::fromDiscoveryDocument($this->idp->discoveryDocument());
    }
}
