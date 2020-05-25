<?php

namespace Informeren\OAuth2\Client\Provider;

use InvalidArgumentException;
use Lcobucci\JWT\Claim;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Lcobucci\JWT\Parser;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;
use Throwable;

class MobilePay extends AbstractProvider
{
    const ENDPOINTS = [
        'dk' => [
            'production' => 'https://admin.mobilepay.dk/account/.well-known/openid-configuration',
            'sandbox' => 'https://sandprod-admin.mobilepay.dk/account/.well-known/openid-configuration',
        ],
        'fi' => [
            'production' => 'https://admin.mobilepay.fi/account/.well-known/openid-configuration',
            'sandbox' => 'https://sandprod-admin.mobilepay.fi/account/.well-known/openid-configuration',
        ],
    ];

    /**
     * @var string
     */
    protected $codeVerifier;

    /**
     * @var string
     */
    protected $merchantVat;

    /**
     * @var array
     */
    protected $configuration;

    /**
     * {@inheritDoc}
     */
    public function __construct(array $options = [], array $collaborators = [])
    {
        $options += [
            'country' => 'dk',
            'environment' => 'sandbox',
        ];

        $this->assertRequiredOptions($options);

        parent::__construct($options, $collaborators);

        $country = strtolower($options['country']);
        $environment = strtolower($options['environment']);

        $this->configure($country, $environment);
    }

    /**
     * @param string $country
     * @param string $environment
     */
    protected function configure(string $country, string $environment)
    {
        if (empty(self::ENDPOINTS[$country][$environment])) {
            $message = sprintf('Invalid country (%s) or environment(%s)', $country, $environment);
            throw new RuntimeException($message);
        }

        $endpoint = self::ENDPOINTS[$country][$environment];

        try {
            $request = $this->getRequest('GET', $endpoint);
            $response = $this->getResponse($request);

            $body = $response->getBody();
            $this->configuration = json_decode($body, true);
        } catch (Throwable $o_O) {
            $message = sprintf('Unable to retrieve OpenID configuration from %s', $endpoint);
            throw new RuntimeException($message);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function getGuarded()
    {
        return [
            'configuration',
        ];
    }

    /**
     * Returns all options that are required.
     *
     * @return array
     */
    protected function getRequiredOptions()
    {
        return [
            'clientId',
            'clientSecret',
            'codeVerifier',
            'country',
            'environment',
            'merchantVat',
            'redirectUri',
        ];
    }

    /**
     * Verifies that all required options have been passed.
     *
     * @param  array $options
     * @return void
     * @throws InvalidArgumentException
     */
    private function assertRequiredOptions(array $options)
    {
        $missing = array_diff_key(array_flip($this->getRequiredOptions()), $options);

        if (!empty($missing)) {
            throw new InvalidArgumentException(
                'Required options not defined: ' . implode(', ', array_keys($missing))
            );
        }
    }

    /**
     * {@inheritDoc}
     */
    public function getBaseAuthorizationUrl()
    {
        return $this->configuration['authorization_endpoint'];
    }

    /**
     * {@inheritDoc}
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->configuration['token_endpoint'];
    }

    /**
     * {@inheritDoc}
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        throw new RuntimeException('Not implemented');
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
