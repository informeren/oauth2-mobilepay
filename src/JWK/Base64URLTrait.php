<?php

namespace Informeren\OAuth2\Client\JWK;

trait Base64URLTrait
{
    public static function base64URLDecode(string $data): string
    {
        $base64 = strtr($data, '-_', '+/');

        return base64_decode($base64, true);
    }

    public static function base64URLEncode(string $data): string
    {
        $encoded = base64_encode($data);

        return rtrim(strtr($encoded, '+/', '-_'), '=');
    }
}
