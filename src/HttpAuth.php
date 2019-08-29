<?php


namespace Angujo\HttpAuth;


use Angujo\HttpAuth\Models\BasicAuth;
use Angujo\HttpAuth\Models\DigestAuth;

/**
 * Class HttpAuth
 *
 * @package Angujo\HttpAuth
 */
class HttpAuth
{
    const SUCCESS        = 0;
    const WRONG_USERNAME = 400;
    const WRONG_PASSWORD = 402;
    const WRONG_RESPONSE = 403;
    const AUTH_BASIC     = 'basic';
    const AUTH_DIGEST    = 'digest';

    private $my_realm = 'angujo/httpauth-realm-2019';

    /**
     * @var DigestAuth
     */
    protected $auth;

    public function __construct($auth)
    {
        if (0 === strcasecmp($auth, self::AUTH_DIGEST)) {
            $this->auth = new DigestAuth();
        } else {
            $auth = new BasicAuth();
        }
        $auth->setRealm($this->my_realm);
    }

    public function setRealm($realm)
    {
        $this->my_realm = $realm;
    }

    public function getUsername()
    {
        return $this->auth->getUsername();
    }

    public function sendHeaders()
    {
        return $this->auth->sendHeaders();
    }

    public function handleLogin(callable $verifier)
    {
        $password = $verifier($this->getUsername());
        if (self::SUCCESS === ($res = $this->auth->verify($this->getUsername(), $password))) {
            return true;
        }
        return $this->loginFail($res);
    }

    private function loginFail($result)
    {
        $this->auth->sendHeaders();
        if ($result === self::WRONG_USERNAME) {
            die('Invalid or wrong Username/password!');
        } elseif ($result === self::WRONG_PASSWORD) {
            die('Invalid or wrong Password/Username!');
        } elseif ($result === self::WRONG_RESPONSE) {
            die('Wrong client connection response!');
        }
        return $result;
    }

    /**
     * @param callable|null $verifier
     *
     * @return HttpAuth|bool|mixed
     */
    public static function digest(callable $verifier = null)
    {
        $me = new self(self::AUTH_DIGEST);
        if ($verifier && is_callable($verifier)) {
            return $me->handleLogin($verifier);
        }
        return $me;
    }
}