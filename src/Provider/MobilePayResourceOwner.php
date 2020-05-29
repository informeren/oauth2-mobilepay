<?php

namespace Informeren\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use RuntimeException;

class MobilePayResourceOwner implements ResourceOwnerInterface
{
    /**
     * @var array
     */
    protected $response;

    /**
     * @param array $response
     */
    public function __construct(array $response)
    {
        $this->response = $response;
    }

    /**
     * {@inheritDoc}
     */
    public function getId()
    {
        if (empty($this->response['merchant_id'])) {
            throw new RuntimeException('Resource owner ID not available');
        }
        return $this->response['merchant_id'];
    }

    /**
     * {@inheritDoc}
     */
    public function toArray()
    {
        return $this->response;
    }
}
