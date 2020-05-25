<?php

namespace Informeren\OAuth2\Client\Test\Provider;

use Informeren\OAuth2\Client\Provider\MobilePayResourceOwner;
use PHPUnit\Framework\TestCase;

class MobilePayResourceOwnerTest extends TestCase
{
    public function testUserConfiguration()
    {
        $response = [
            'merchant_id' => 'b1d967ff-befd-4eb1-88b1-bc9147cebb3f',
        ];

        $owner = new MobilePayResourceOwner($response);

        $this->assertInstanceOf(MobilePayResourceOwner::class, $owner);
        $this->assertEquals($response['merchant_id'], $owner->getId());
        $this->assertEqualsCanonicalizing($response, $owner->toArray());
    }
}
