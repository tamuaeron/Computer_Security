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

function printStepInfo($step, $sender, $receiver, $encryptedMessage, $decryptedMessage, $hashedMessage, $authenticated) {
    $hashedEncryptedMessage = hashMessage($encryptedMessage);
    $hashedDecryptedMessage = hashMessage($decryptedMessage);
    $hashedReceivedMessage = hashMessage($hashedMessage);

    echo "Step $step: $sender -> $receiver\n";
    echo "  - $sender sends (hashed): $hashedEncryptedMessage\n";
    echo "  - $receiver receives and decrypts (hashed): $hashedDecryptedMessage\n";
    echo "  - Hashed Message for Authentication: $hashedMessage\n";
    echo "  - Authentication: " . ($authenticated ? "Successful" : "Failed") . "\n";
    echo "\n";
    return $authenticated;
}

function simulateKeyExchange($sender, $receiver, &$sharedKey) {
    // Simulate key exchange between $sender and $receiver
    $sharedKey = rand(1, 1000);
    $hashedSharedKey = hashMessage($sharedKey);
    echo "$sender and $receiver share key (hashed): $hashedSharedKey\n";
    return $sharedKey;
}

function simulateNeedhamSchroeder() {
    // Initialization
    $K_AS = simulateKeyExchange('A', 'S', $dummy);  // Pre-shared key between A and S
    $K_BS = simulateKeyExchange('B', 'S', $dummy);  // Pre-shared key between B and S
    $K_AB = simulateKeyExchange('A', 'B', $dummy);  // Pre-shared key between A and B

    // Display pre-shared keys
    echo "Pre-shared key between A and S: $K_AS (hashed: " . hashMessage($K_AS) . ")\n";
    echo "Pre-shared key between B and S: $K_BS (hashed: " . hashMessage($K_BS) . ")\n";
    echo "Pre-shared key between A and B: $K_AB (hashed: " . hashMessage($K_AB) . ")\n";

    // Step 1: A -> S: A, B, NA (A's nonce)
    $NA = generateNonce();
    $messageAtoS = "A, B, $NA";
    $hashedMessageAtoS = hashMessage($messageAtoS);
    $encryptedMessageAtoS = encrypt($messageAtoS, $K_AS);
    $decryptedMessageAtoS = decrypt($encryptedMessageAtoS, $K_AS);
    $authenticatedAtoS = printStepInfo(1, 'A', 'S', $encryptedMessageAtoS, $decryptedMessageAtoS, $hashedMessageAtoS, $hashedMessageAtoS === hashMessage($decryptedMessageAtoS));

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
    $authenticatedStep2 = printStepInfo(2, 'S', 'B', $encryptedMessageStoB, $decryptedMessageStoB, $hashedK_AB, $hashedK_AB === hashMessage($decryptedMessageStoB));

    // Record K_AB and Message 3 for the replay attack
    $recordedK_AB = $K_AB;
    $recordedMessage3 = "{$hashedK_AB}, B";
    $recordedEncryptedMessage3 = encrypt($recordedMessage3, $K_AS);

    // Display information for replay attack recording
    echo "Replay Attack Recorded:\n";
    echo "  - Recorded K_AB (hashed): " . hashMessage($recordedK_AB) . "\n";
    echo "  - Recorded Message 3 (encrypted): $recordedEncryptedMessage3\n";
    echo "\n";

    // Step 3: B -> S: {NA, A, K_AB}K_BS
    $messageBtoS = $messageStoB;
    $encryptedMessageBtoS = encrypt($messageBtoS, $K_BS);
    $decryptedMessageBtoS = decrypt($encryptedMessageBtoS, $K_BS);

    // Display information for Step 3
    $authenticatedStep3 = printStepInfo(3, 'B', 'S', $encryptedMessageBtoS, $decryptedMessageBtoS, $hashedK_AB, $hashedK_AB === hashMessage($decryptedMessageBtoS));

    // Step 4: S -> A: {K_AB, B}K_AS
    $messageStoA = "{$hashedK_AB}, B";
    $encryptedMessageStoA = encrypt($messageStoA, $K_AS);
    $decryptedMessageStoA = decrypt($encryptedMessageStoA, $K_AS);

    // Display information for Step 4
    $authenticatedStep4 = printStepInfo(4, 'S', 'A', $encryptedMessageStoA, $decryptedMessageStoA, $hashedK_AB, $hashedK_AB === hashMessage($decryptedMessageStoA));

    // Step 5: A -> B: {K_AB, A}K_BS
    $messageAtoB = "{$hashedK_AB}, A";
    $encryptedMessageAtoB = encrypt($messageAtoB, $K_BS);
    $decryptedMessageAtoB = decrypt($encryptedMessageAtoB, $K_BS);

    // Display information for Step 5
    $authenticatedStep5 = printStepInfo(5, 'A', 'B', $encryptedMessageAtoB, $decryptedMessageAtoB, $hashedK_AB, $hashedK_AB === hashMessage($decryptedMessageAtoB));

    // Protocol completion
    echo "Protocol completed successfully. Shared session key (hashed K_AB): $hashedK_AB\n";

    // Return the shared key and recorded information for the replay attack
    return [$K_BS, $recordedK_AB, $recordedEncryptedMessage3];
}

function simulateReplayAttack($K_BS, $recordedK_AB, $recordedEncryptedMessage3) {
    // Initialization for the replay attack
    $attackerKAB = $recordedK_AB;  // Attacker's knowledge of K_AB

    // Step 6: E (Attacker) -> B: {K_AB, A}K_BS
    $messageEtoB = "{" . encrypt("{$recordedK_AB}, A", $K_BS) . "}";
    $encryptedMessageEtoB = encrypt($messageEtoB, $K_BS);
    $decryptedMessageEtoB = decrypt($encryptedMessageEtoB, $K_BS);

    // Display information for Step 6
    $authenticatedStep6 = printStepInfo(6, 'E (Attacker)', 'B', $encryptedMessageEtoB, $decryptedMessageEtoB, "", $recordedEncryptedMessage3 === $encryptedMessageEtoB);

    // Step 7: B -> E: {NB}K_AB
    $NB = generateNonce();
    $hashedNB = hashMessage($NB);
    $messageBtoE = "{$NB}";
    $encryptedMessageBtoE = encrypt($messageBtoE, $attackerKAB);
    $decryptedMessageBtoE = decrypt($encryptedMessageBtoE, $attackerKAB);

    // Display information for Step 7
    $authenticatedStep7 = printStepInfo(7, 'B', 'E (Attacker)', $encryptedMessageBtoE, $decryptedMessageBtoE, $hashedNB, $hashedNB === hashMessage($decryptedMessageBtoE));

    // Step 8: E -> B: {NB-1}K_AB
    $NB_minus_1 = $NB - 1;
    $hashedNB_minus_1 = hashMessage($NB_minus_1);
    $messageEtoB_2 = "{$NB_minus_1}";
    $encryptedMessageEtoB_2 = encrypt($messageEtoB_2, $attackerKAB);
    $decryptedMessageEtoB_2 = decrypt($encryptedMessageEtoB_2, $attackerKAB);

    // Display information for Step 8
    $authenticatedStep8 = printStepInfo(8, 'E (Attacker)', 'B', $encryptedMessageEtoB_2, $decryptedMessageEtoB_2, $hashedNB_minus_1, $hashedNB_minus_1 === hashMessage($decryptedMessageEtoB_2));

    // Check if authentication is successful for all steps
    return $authenticatedStep6 && $authenticatedStep7 && $authenticatedStep8;
}

// Run the simulation and get the session key
[$K_BS, $recordedK_AB, $recordedEncryptedMessage3] = simulateNeedhamSchroeder();

// Run the replay attack simulation using the obtained session key
$replayAttackSuccess = simulateReplayAttack($K_BS, $recordedK_AB, $recordedEncryptedMessage3);

if ($replayAttackSuccess) {
    echo "Replay attack simulation successful. E impersonated A to communicate with B.\n";
} else {
    echo "Replay attack simulation failed. Authentication checks did not pass.\n";
}

?>
