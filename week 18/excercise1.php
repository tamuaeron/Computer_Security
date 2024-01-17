<?php

function generateShortHMAC($key, $message) {
    $fullHMAC = hash_hmac('sha256', $message, $key, true); // Using SHA-256 as an example
    $shortHMAC = substr($fullHMAC, 0, 2); // Truncate to 16 bits (2 bytes)
    return $shortHMAC;
}

// Example usage with actual values
$sharedSecretKey = "superSecretKey"; // Replace with the actual shared secret key
$message = "Alice, Bob, £10"; // Replace with the actual message
$shortHMAC = generateShortHMAC($sharedSecretKey, $message);

echo "16-bit HMAC: $shortHMAC\n";

?>
