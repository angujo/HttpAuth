<?php


include_once '../vendor/autoload.php';

use Angujo\HttpAuth\HttpAuth;

echo '<pre>';
HttpAuth::digest(function($username){
    return 'does';
});