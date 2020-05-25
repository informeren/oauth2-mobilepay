<?php

namespace Informeren\OAuth2\Client\Provider;

use Lcobucci\JWT\Claim;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Lcobucci\JWT\Parser;
use Psr\Http\Message\ResponseInterface;

class MobilePay extends AbstractProvider
{
    /**
     * @var string
     */
    protected $codeVerifier;

    /**
     * @var string
     */
    protected $merchantVat;

    /**
     * {@inheritDoc}
     */
    public function getBaseAuthorizationUrl()
    {
        return 'https://sandprod-admin.mobilepay.dk/account/connect/authorize';
    }

    /**
     * {@inheritDoc}
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return 'https://api.sandbox.mobilepay.dk/merchant-authentication-openidconnect/connect/token';
    }

    /**
     * {@inheritDoc}
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        throw new \RuntimeException('Not implemented');
    }

    /**
     * {@inheritDoc}
     */
    public function getAccessToken($grant, array $options = [])
    {
        $options['code_verifier'] = $this->codeVerifier;

        return parent::getAccessToken($grant, $options);
    }

    /**
     * {@inheritDoc}
     */
    protected function getAuthorizationParameters(array $options)
    {
        $options['approval_prompt'] = null;

        $options['code_challenge_method'] = 'S256';
        $options['code_challenge'] = $this->codeChallenge($this->codeVerifier);

        $options['merchant_vat'] = $this->merchantVat;

        $options['nonce'] = $this->getRandomState();

        return parent::getAuthorizationParameters($options);
    }

    protected function codeChallenge(string $verifier): string
    {
        $hash = hash('sha256', $verifier, true);

        $encoded = base64_encode($hash);

        return rtrim(strtr($encoded, '/+', '_-'), '=');
    }

    /**
     * {@inheritDoc}
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if (empty($data['error'])) {
            return;
        }

        $code = 0;

        throw new IdentityProviderException($data['error'], $code, $data);
    }

    /**
     * {@inheritDoc}
     */
    protected function fetchResourceOwnerDetails(AccessToken $token)
    {
        $parser = new Parser();

        $jwt = $parser->parse($token->getToken());

        $claims = $jwt->getClaims();

        return array_reduce($claims, function (array $carry, Claim $item) {
            $carry[$item->getName()] = $item->getValue();
            return $carry;
        }, []);
    }

    /**
     * {@inheritDoc}
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new MobilePayResourceOwner($response);
    }

    /**
     * {@inheritDoc}
     */
    protected function getDefaultScopes()
    {
        return [];
    }

    /**
     * {@inheritDoc}
     */
    protected function getScopeSeparator()
    {
        return ' ';
    }
}
