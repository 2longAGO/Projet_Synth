<?php
// https://github.com/defuse/php-encryption/blob/master/docs/Tutorial.md
use Defuse\Crypto\Crypto;
use Defuse\Crypto\KeyProtectedByPassword;
use Defuse\Crypto\Key;

$user_key_encoded = // ... get it out of the cookie ...
$user_locked_key = KeyProtectedByPassword::loadFromAsciiSafeString($user_key_encoded)
$user_key = $user_locked_key->unlockKey($user_key_encoded);

// ...

$credit_card_number = // ... get credit card number from the user
$encrypted_card_number = Crypto::encrypt($credit_card_number, $user_key);
?>