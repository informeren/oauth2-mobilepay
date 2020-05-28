<?php

namespace Informeren\OAuth2\Client\Provider;

use Informeren\OAuth2\Client\JWK\KeySet;
use InvalidArgumentException;
use Lcobucci\JWT\Claim;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\ValidationData;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Lcobucci\JWT\Parser;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;
use Throwable;

class MobilePay extends AbstractProvider
{
    /**
     * @var array
     */
    protected $configuration;

    /**
     * {@inheritDoc}
     */
    public function __construct(array $options = [], array $collaborators = [])
    {
        $this->assertRequiredOptions($options);

        parent::__construct($options, $collaborators);

        $this->configure($options['discoveryUri']);
    }

    /**
     * @param string $url
     */
    protected function configure(string $url)
    {
        try {
            $request = $this->getRequest('GET', $url);
            $response = $this->getResponse($request);

            $body = $response->getBody();
            $this->configuration = json_decode($body, true);
        } catch (Throwable $o_O) {
            $message = sprintf('Unable to retrieve OpenID configuration from %s', $url);
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
     * Returns all required options.
     *
     * @return array
     */
    protected function getRequiredOptions()
    {
        return [
            'clientId',
            'clientSecret',
            'discoveryUri',
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
    protected function getAuthorizationParameters(array $options)
    {
        $options['approval_prompt'] = null;

        $options['code_challenge_method'] = 'S256';
        $options['code_challenge'] = $this->codeChallenge($options['code_verifier']);
        unset($options['code_verifier']);

        $options['nonce'] = $this->getRandomState();

        return parent::getAuthorizationParameters($options);
    }

    /**
     * Compute the OpenID Connect code challenge.
     *
     * @see https://developer.mobilepay.dk/node/1354
     *
     * @param string $verifier
     *   A cryptographically random string.
     * @return string
     *   A challenge derived from the verifier string.
     */
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
        if ($response->getStatusCode() !== 200 || empty($data['access_token'])) {
            throw new IdentityProviderException('Invalid reponse', 0, $data);
        }

        $parser = new Parser();

        $token = $parser->parse($data['id_token']);

        $validator = new ValidationData();
        $validator->setIssuer($this->configuration['issuer']);
        $validator->setAudience($this->clientId);

        if (!$token->validate($validator)) {
            throw new IdentityProviderException('Invalid token', 0, $data);
        }

        if ($token->hasHeader('kid')) {
            $request = $this->getRequest('GET', $this->configuration['jwks_uri']);
            $response = $this->getResponse($request);

            $keyset = KeySet::fromJson($response->getBody());

            $key = $keyset->find($token->getHeader('kid'));

            $signer = new Sha256();
            if ($token->verify($signer, $key->toPem())) {
                return;
            }
        }

        throw new IdentityProviderException('Unable to verify token signature', 0, $data);
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
