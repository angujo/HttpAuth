<?php

namespace Angujo\HttpAuth\Models;

/**
 * Class AuthAbstract
 */
abstract class AuthAbstract
{
    protected $_realm;
    protected $_username;
    protected $_password;

    /**
     * @param mixed $realm
     *
     * @return AuthAbstract
     */
    public function setRealm(&$realm)
    {
        $this->_realm =& $realm;
        return $this;
    }

    public abstract function getUsername();

    public abstract function verify($username, $password);
}