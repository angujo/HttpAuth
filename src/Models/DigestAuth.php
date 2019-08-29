<?php

namespace Angujo\HttpAuth\Models;

use Angujo\HttpAuth\Exceptions\HttpAuthException;
use Angujo\HttpAuth\HttpAuth;

/**
 * Class DigestAuth
 */
class DigestAuth extends AuthAbstract
{
    /**
     * @var string
     */
    private $_nonce;
    /**
     * @var string
     */
    private $_cnonce;
    /**
     * @var string
     */
    private $_nc;
    /**
     * @var string
     */
    private $_qop;
    /**
     * @var string
     */
    private $_uri;
    /**
     * @var string
     */
    private $_response;
    private $_request_method;

    /**
     * DigestAuth constructor.
     *
     * @throws HttpAuthException
     */
    public function __construct()
    {
        $this->parse();
        $this->_request_method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';
    }

    public function getUsername()
    {
        return $this->_username;
    }

    public function verify($username, $password)
    {
        $this->parse();
        $x = 0;
        if (!(strcmp($this->_username, $username) === 0)) {
            $x |= HttpAuth::WRONG_USERNAME;
        }
        if (!(strcmp($this->_response, $this->validResponse($password)) === 0)) {
            $x |= HttpAuth::WRONG_RESPONSE;
        }
        return $x;
    }

    private function parse()
    {
        $needed_parts = ['nonce' => 1, 'nc' => 1, 'cnonce' => 1, 'qop' => 1, 'username' => 1, 'uri' => 1, 'response' => 1];
        $data         = [];
        $keys         = implode('|', array_keys($needed_parts));
        preg_match_all('@('.$keys.')=(?:([\'"])([^\2]+?)\2|([^\s,]+))@', self::getAuthDigest(), $matches, PREG_SET_ORDER);
        foreach ($matches as $m) {
            $data[$m[1]] = $m[3] ? $m[3] : $m[4];
            unset($needed_parts[$m[1]]);
        }
        if ($needed_parts) {
            throw new HttpAuthException('Missing Authentication Parameters: '.implode(', ', $needed_parts));
        }
        foreach ($data as $prop => $datum) {
            $this->{"_{$prop}"} = $datum;
        }
    }

    private function getAuthDigest()
    {
        $digest = null;
        if (isset($_SERVER['PHP_AUTH_DIGEST'])) {
            $digest = $_SERVER['PHP_AUTH_DIGEST'];
        } elseif (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            if (strpos(strtolower($_SERVER['HTTP_AUTHORIZATION']), 'digest') === 0) {
                $digest = substr($_SERVER['HTTP_AUTHORIZATION'], 7);
            }
        }
        return $digest;
    }

    public function sendHeaders()
    {
        header('HTTP/1.1 401 Unauthorized');
        header(sprintf('WWW-Authenticate: Digest realm="%s", qop="auth", nonce="%s",opaque="%s"', $this->_realm, uniqid(), md5($this->_realm)));
    }

    private function validResponse($password)
    {
        $A1       = md5(sprintf('%s:%s:%s', $this->_username, $this->_realm, $password));
        $A2       = md5(sprintf('%s:%s', $this->_request_method, $this->_uri));
        $response = md5(sprintf('%s:%s:%s:%s:%s:%s', $A1, $this->_nonce, $this->_nc, $this->_cnonce, $this->_qop, $A2));
        return $response;
    }

}