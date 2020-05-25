<?php

namespace Informeren\OAuth2\Client\JWK;

use phpseclib\Crypt\RSA;
use phpseclib\Math\BigInteger;

class Key
{
    use Base64URLTrait;

    /**
     * @var string
     */
    protected $kid;

    /**
     * @var string
     */
    protected $exponent;

    /**
     * @var string
     */
    protected $modulus;

    /**
     * Key constructor.
     * @param string $kid
     */
    public function __construct(string $kid)
    {
        $this->kid = $kid;
    }

    public static function fromState(array $state)
    {
        $key = new self($state['kid']);

        $key->setExponent($state['e']);
        $key->setModulus($state['n']);

        return $key;
    }

    public function toPem(): string
    {
        $rsa = new RSA();

        $exponent = self::base64URLDecode($this->exponent);
        $modulus = self::base64URLDecode($this->modulus);

        $rsa->loadKey([
            'e' => new BigInteger($exponent, 256),
            'n' => new BigInteger($modulus, 256),
        ]);

        return $rsa->getPublicKey();
    }

    /**
     * @return string
     */
    public function getId(): string
    {
        return $this->kid;
    }

    /**
     * @return string
     */
    public function getExponent(): string
    {
        return $this->exponent;
    }

    /**
     * @param string $exponent
     */
    public function setExponent(string $exponent): void
    {
        $this->exponent = $exponent;
    }

    /**
     * @return string
     */
    public function getModulus(): string
    {
        return $this->modulus;
    }

    /**
     * @param string $modulus
     */
    public function setModulus(string $modulus): void
    {
        $this->modulus = $modulus;
    }
}
