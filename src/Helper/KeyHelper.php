<?php

namespace Informeren\OAuth2\Client\Helper;

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use phpseclib\Crypt\RSA;
use phpseclib\Math\BigInteger;

class KeyHelper
{
    public static function keyToPem(JWK $key)
    {
        $rsa = new RSA();

        $exponent = Base64Url::decode($key->get('e'));
        $modulus = Base64Url::decode($key->get('n'));

        $rsa->loadKey([
            'e' => new BigInteger($exponent, 256),
            'n' => new BigInteger($modulus, 256),
        ]);

        return $rsa->getPublicKey();
    }
}
