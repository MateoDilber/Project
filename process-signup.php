<?php

if (empty($_POST["name"])) {
    die("Schrijf je naam!");
}

if ( ! filter_var($_POST["email"], FILTER_VALIDATE_EMAIL)) {
    die("Schrijf je mail gewoon man");
}

if (strlen($_POST["password"]) < 8) {
    die("Bro, minimaal 8 karakters lang.. ff serieus");
}

if ( ! preg_match("/[a-z]/i", $_POST["password"])) {
    die("Kom op man er moet toch wel een letter in?");
}

if ( ! preg_match("/[0-9]/", $_POST["password"])) {
    die("Er moet nog een cijfer in");
}

if ($_POST["password"] !== $_POST["password_confirmation"]) {
    die("Bro je schrijft niet hetzelfde password ff serieus");
}

$password_hash = password_hash($_POST["password"], PASSWORD_DEFAULT);

$mysqli = require __DIR__ . "/database.php";

$sql = "INSERT INTO user (name, email, password_hash)
        VALUES (?, ?, ?)";
        
$stmt = $mysqli->stmt_init();

if ( ! $stmt->prepare($sql)) {
    die("SQL error: " . $mysqli->error);
}

$stmt->bind_param("sss",
                  $_POST["name"],
                  $_POST["email"],
                  $password_hash);
                  
if ($stmt->execute()) {

    header("Location: signup-success.html");
    exit;
    
} else {
    
    if ($mysqli->errno === 1062) {
        die("email already taken");
    } else {
        die($mysqli->error . " " . $mysqli->errno);
    }
}








