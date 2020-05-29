<?php

namespace Informeren\OAuth2\Client\Test\Provider;

use Base64Url\Base64Url;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Informeren\OAuth2\Client\Provider\MobilePay;
use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class MobilePayTest extends TestCase
{
    protected $keypair;

    protected $mock;

    protected $provider;

    public function __construct(?string $name = null, array $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);

        $this->keypair = openssl_pkey_new();
    }

    public function setUp() :void
    {
        $payload = [
            'issuer' => 'mock_issuer',
            'authorization_endpoint' => 'mock_authorization_endpoint',
            'token_endpoint' => 'mock_token_endpoint',
            'jwks_uri' => 'mock_jwks_uri',
        ];

        $this->mock = new MockHandler([
            new Response(200, [], json_encode($payload)),
        ]);

        $handlerstack = HandlerStack::create($this->mock);

        $collaborators['httpClient'] = new Client(['handler' => $handlerstack]);

        $options = [
            'clientId' => 'mock_client_id',
            'clientSecret' => 'mock_client_id',
            'discoveryUri' => 'mock_discovery_uri',
            'redirectUri' => 'mock_redirect_uri',
        ];

        $this->provider = new MobilePay($options, $collaborators);
    }

    public function testAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl([
            'scope' => ['openid', 'subscriptions', 'offline_access'],
            'response_type' => 'code id_token',
            'response_mode' => 'fragment',
            'code_verifier' => 'MVLkNAsW0uy5PnH3L3YwUzXqcPzMfNeKPIfD4K32MN4',
            'merchant_vat' => 'DK12345678',
        ]);

        $uri = parse_url($url);
        parse_str($uri['query'], $query);

        $this->assertArrayHasKey('client_id', $query);
        $this->assertArrayHasKey('code_challenge', $query);
        $this->assertArrayHasKey('code_challenge_method', $query);
        $this->assertArrayHasKey('merchant_vat', $query);
        $this->assertArrayHasKey('nonce', $query);
        $this->assertArrayHasKey('redirect_uri', $query);
        $this->assertArrayHasKey('response_mode', $query);
        $this->assertArrayHasKey('response_type', $query);
        $this->assertArrayHasKey('scope', $query);
        $this->assertArrayHasKey('state', $query);

        $this->assertArrayNotHasKey('approval_prompt', $query);

        $this->assertEquals('S256', $query['code_challenge_method']);
        $this->assertEquals('fragment', $query['response_mode']);
        $this->assertEquals('code id_token', $query['response_type']);
    }

    public function testTokenUrl()
    {
        $url = $this->provider->getBaseAccessTokenUrl([]);

        $this->assertEquals('mock_token_endpoint', $url);
    }

    public function testDefaultScopes()
    {
        $url = $this->provider->getAuthorizationUrl([
            'response_type' => 'code id_token',
            'response_mode' => 'fragment',
            'code_verifier' => 'mock_code_verifier',
            'merchant_vat' => 'DK12345678',
        ]);

        $uri = parse_url($url);
        parse_str($uri['query'], $query);

        $this->assertEmpty($query['scope']);
    }

    public function testScopes()
    {
        $scopeSeparator = ' ';

        $options = [
            'scope' => [uniqid(), uniqid()],
            'code_verifier' => 'mock_code_verifier',
        ];

        $query = ['scope' => implode($scopeSeparator, $options['scope'])];

        $url = $this->provider->getAuthorizationUrl($options);
        $encodedScope = http_build_query($query, null, null,  PHP_QUERY_RFC3986);

        $this->assertStringContainsString($encodedScope, $url);
    }

    public function testIdentityProviderException()
    {
        $this->expectException(IdentityProviderException::class);

        $this->mock->reset();
        $this->mock->append(
            new Response(500, [], '{}'),
        );

        /** @noinspection PhpUnhandledExceptionInspection */
        $this->provider->getAccessToken('refresh_token', [
           'refresh_token' => 'mock_refresh_token',
        ]);
    }

    public function testRefreshToken()
    {
        $this->mock->reset();
        $this->mock->append(
            new Response(200, [], $this->getTokenResponse()),
            new Response(200, [], $this->getJwksResponse()),
        );

        /** @noinspection PhpUnhandledExceptionInspection */
        $token = $this->provider->getAccessToken('refresh_token', [
            'refresh_token' => 'mock_refresh_token',
        ]);

        $this->assertFalse($token->hasExpired());

        $values = $token->getValues();

        $this->assertEquals('Bearer', $values['token_type']);
        $this->assertEquals('mock_scope', $values['scope']);
    }

    public function testInvalidRefreshToken()
    {
        $this->expectException(IdentityProviderException::class);

        $data = $this->getTokenData('invalid_issuer');

        $this->mock->reset();
        $this->mock->append(
            new Response(200, [], json_encode($data)),
        );

        /** @noinspection PhpUnhandledExceptionInspection */
        $this->provider->getAccessToken('refresh_token', [
            'refresh_token' => 'mock_refresh_token',
        ]);
    }

    public function testInvalidSignature()
    {
        $this->expectException(IdentityProviderException::class);

        $this->mock->reset();
        $this->mock->append(
            new Response(200, [], $this->getTokenResponse()),
            new Response(200, [], json_encode(['keys' => []])),
        );

        /** @noinspection PhpUnhandledExceptionInspection */
        $this->provider->getAccessToken('refresh_token', [
            'refresh_token' => 'mock_refresh_token',
        ]);
    }

    public function testResouceOwner()
    {
        $this->mock->reset();
        $this->mock->append(
            new Response(200, [], $this->getTokenResponse()),
            new Response(200, [], $this->getJwksResponse()),
        );

        /** @noinspection PhpUnhandledExceptionInspection */
        $token = $this->provider->getAccessToken('refresh_token', [
            'refresh_token' => 'mock_refresh_token',
        ]);

        /** @var AccessToken $token */
        $user = $this->provider->getResourceOwner($token);

        $this->assertEquals('f004fe14-f048-4628-91b0-a86aeaf3f18c', $user->getId());
    }

    private function getTokenData(string $issuer)
    {
        $time = time();

        openssl_pkey_export($this->keypair, $private_key);

        $signer = new Sha256();
        $signer_key = new Key($private_key);

        $builder = new Builder();
        $token = $builder
            ->withHeader('alg', 'RS256')
            ->withHeader('kid', 'B2B02429749EF96C7A5EAB70C83E7C943C19DAE4')
            ->issuedBy($issuer)
            ->identifiedBy('mock_identifier')
            ->issuedAt($time)
            ->canOnlyBeUsedAfter($time)
            ->expiresAt($time + 3600)
            ->withClaim('merchant_id', 'f004fe14-f048-4628-91b0-a86aeaf3f18c')
            ->getToken($signer, $signer_key);

        return [
            'id_token' => (string)$token,
            'access_token' => (string)$token,
            'expires_in' => 300,
            'token_type' => 'Bearer',
            'refresh_token' => 'mock_refresh_token',
            'scope' => 'mock_scope',
        ];
    }

    private function getTokenResponse()
    {
        $data = $this->getTokenData('mock_issuer');

        return json_encode($data);
    }

    private function getJwksResponse()
    {
        $details = openssl_pkey_get_details($this->keypair);

        $data = [
            'kid' => 'B2B02429749EF96C7A5EAB70C83E7C943C19DAE4',
            'kty' => 'RSA',
            'use' => 'sig',
            'n' => Base64Url::encode($details['rsa']['n']),
            'e' => Base64Url::encode($details['rsa']['e']),
        ];

        $key = new JWK($data);

        $keyset = new JWKSet([$key]);

        return json_encode($keyset);
    }

    public function testDiscoveryException()
    {
        $this->expectException(RuntimeException::class);

        $options = [
            'clientId' => 'mock_client_id',
            'clientSecret' => 'mock_client_id',
            'discoveryUri' => 'mock_discovery_uri',
            'redirectUri' => 'mock_redirect_uri',
        ];

        $this->provider = new MobilePay($options);
    }

    public function testRequiredOptionsException()
    {
        $this->expectException(InvalidArgumentException::class);

        $options = [
            'clientId' => 'mock_client_id',
            'clientSecret' => 'mock_client_id',
        ];

        $this->provider = new MobilePay($options);
    }

    public function testResourceOwnerDetailsException()
    {
        $this->expectException(RuntimeException::class);

        $token = new AccessToken(['access_token' => 'mock_token']);

        $this->provider->getResourceOwnerDetailsUrl($token);
    }
}
