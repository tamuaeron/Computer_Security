<?php

function encrypt($message, $key) {
    // Simulate symmetric encryption
    $encryptedMessage = "";
    for ($i = 0; $i < strlen($message); $i++) {
        $encryptedMessage .= chr((ord($message[$i]) + $key) % 128);
    }
    return $encryptedMessage;
}

function decrypt($encryptedMessage, $key) {
    // Simulate symmetric decryption
    $decryptedMessage = "";
    for ($i = 0; $i < strlen($encryptedMessage); $i++) {
        $decryptedMessage .= chr((ord($encryptedMessage[$i]) - $key + 128) % 128);
    }
    return $decryptedMessage;
}

function generateNonce() {
    // Generate a random nonce (number used once)
    return rand(1000, 9999);
}

function hashMessage($message) {
    // Simulate message authentication
    return hash('sha256', $message);
}

function printStepInfo($step, $sender, $receiver, $encryptedMessage, $decryptedMessage, $authenticated) {
    echo "Step $step: $sender -> $receiver\n";
    echo "  - $sender sends: $encryptedMessage\n";
    echo "  - $receiver receives and decrypts: $decryptedMessage\n";
    echo "  - Authentication: " . ($authenticated ? "Successful" : "Failed") . "\n";
    echo "\n";
}

function simulateKeyExchange($sender, $receiver, &$sharedKey) {
    // Simulate key exchange between $sender and $receiver
    $sharedKey = rand(1, 1000);
    echo "$sender and $receiver share key: $sharedKey (hashed: " . hashMessage($sharedKey) . ")\n";
    return $sharedKey;
}

function simulateNeedhamSchroeder() {
    // Initialization
    $K_AS = simulateKeyExchange('A', 'S', $dummy);  // Pre-shared key between A and S
    $K_BS = simulateKeyExchange('B', 'S', $dummy);  // Pre-shared key between B and S
    $K_AB = null;  // Session key shared between A and B

    // Display pre-shared keys
    echo "Pre-shared key between A and S: $K_AS (hashed: " . hashMessage($K_AS) . ")\n";
    echo "Pre-shared key between B and S: $K_BS (hashed: " . hashMessage($K_BS) . ")\n";

    // Step 1: A -> S: A, B, NA (A's nonce)
    $NA = generateNonce();
    $messageAtoS = "A, B, $NA";
    $hashedMessageAtoS = hashMessage($messageAtoS);
    $encryptedMessageAtoS = encrypt($messageAtoS, $K_AS);
    $decryptedMessageAtoS = decrypt($encryptedMessageAtoS, $K_AS);
    $authenticatedAtoS = hashMessage($decryptedMessageAtoS) === $hashedMessageAtoS;

    // Display information for Step 1
    printStepInfo(1, 'A', 'S', $encryptedMessageAtoS, $decryptedMessageAtoS, $authenticatedAtoS);

    // Stop the protocol if authentication fails
    if (!$authenticatedAtoS) {
        die("Authentication failed. Stopping the protocol.\n");
    }

    // Step 2: S -> B: {NA, A, K_AB}K_BS
    $K_AB = generateNonce(); // Simulating a session key for A and B
    $hashedK_AB = hashMessage($K_AB);
    $messageStoB = "{$NA}, A, {$K_AB}";
    $encryptedMessageStoB = encrypt($messageStoB, $K_BS);
    $decryptedMessageStoB = decrypt($encryptedMessageStoB, $K_BS);

    // Display information for Step 2
    printStepInfo(2, 'S', 'B', $encryptedMessageStoB, $decryptedMessageStoB, true);

    // Step 3: B -> S: {NA, A, K_AB}K_BS
    $messageBtoS = $messageStoB;
    $encryptedMessageBtoS = encrypt($messageBtoS, $K_BS);
    $decryptedMessageBtoS = decrypt($encryptedMessageBtoS, $K_BS);

    // Display information for Step 3
    printStepInfo(3, 'B', 'S', $encryptedMessageBtoS, $decryptedMessageBtoS, true);

    // Step 4: S -> A: {K_AB, B}K_AS
    $messageStoA = "{$hashedK_AB}, B";
    $encryptedMessageStoA = encrypt($messageStoA, $K_AS);
    $decryptedMessageStoA = decrypt($encryptedMessageStoA, $K_AS);

    // Display information for Step 4
    printStepInfo(4, 'S', 'A', $encryptedMessageStoA, $decryptedMessageStoA, true);

    // Step 5: A -> B: {K_AB, A}K_BS
    $messageAtoB = "{$hashedK_AB}, A";
    $encryptedMessageAtoB = encrypt($messageAtoB, $K_BS);
    $decryptedMessageAtoB = decrypt($encryptedMessageAtoB, $K_BS);

    // Display information for Step 5
    printStepInfo(5, 'A', 'B', $encryptedMessageAtoB, $decryptedMessageAtoB, true);

    // Protocol completion
    echo "Protocol completed successfully. Shared session key (hashed K_AB): $hashedK_AB\n";
}

// Run the simulation
simulateNeedhamSchroeder();

?>
