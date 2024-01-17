<?php
// Replace with the actual URL of your password list
$passwordListUrl = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/phpbb.txt";
$passwords = file_get_contents($passwordListUrl);
echo json_encode(explode("\n", $passwords));
?>
