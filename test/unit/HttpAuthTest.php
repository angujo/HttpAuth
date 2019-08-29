<?php

namespace unit;

use Angujo\HttpAuth\HttpAuth;
use PHPUnit\Framework\TestCase;

class HttpAuthTest extends TestCase
{
    public function setUp(): Void
    {
        self::assertTrue(true);
    }

    public function testAuths()
    {
        HttpAuth::digest(function($username){
            echo 'Logs in!';
        });
    }
}
