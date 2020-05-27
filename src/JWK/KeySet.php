<?php

namespace Informeren\OAuth2\Client\JWK;

use RuntimeException;

class KeySet
{

    /**
     * @var Key[]
     */
    protected $keys;

    public function __construct()
    {
        $this->keys = [];
    }

    public static function fromJson(string $json): KeySet
    {
        $data = json_decode($json, true);

        if (empty($data['keys'])) {
            $message = 'No keys available';
            throw new RuntimeException($message);
        }

        $keyset = new self();

        foreach ($data['keys'] as $key) {
            if ($key['kty'] !== 'RSA') {
                continue;
            }

            $rsa = Key::fromState($key);

            $keyset->add($rsa);
        }

        return $keyset;
    }

    public function add(Key $key)
    {
        $this->keys[] = $key;
    }

    public function find(string $id): Key
    {
        $keys = array_filter($this->keys, function (Key $key) use ($id) {
            return $key->getId() === $id;
        });

        if (count($keys) !== 1) {
            $message = sprintf('Key not found: %s', $id);
            throw new RuntimeException($message);
        }

        return reset($keys);
    }
}
