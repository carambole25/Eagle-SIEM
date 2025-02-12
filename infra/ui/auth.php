<?php

function base64UrlEncode($data) {
    return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
}

if (isset($_POST['username']) &&  isset($_POST['password'])) {
    $host = 'db';
    $dbname = 'eagle_db';
    $username = 'changeme_MYSQL_USER';
    $password = 'changeme_MYSQL_PASSWORD';

    try {
        $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8", $username, $password);
    
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        
    } catch (PDOException $e) {
        die("Erreur de connexion : " . $e->getMessage());
    }

    $login = htmlspecialchars($_POST['username']);
    $password = htmlspecialchars($_POST['password']);

    $sql = "SELECT * FROM ui_users WHERE username = ?";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$login]);

    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($password, $user['pass'])) {
        $base64UrlHeader = base64UrlEncode(json_encode(["alg" => "HS256", "typ" => "JWT"]));
        $base64UrlPayload = base64UrlEncode(json_encode(["user" => $user['username']]));
        $base64UrlSignature = hash_hmac('sha256', $base64UrlHeader . '.' . $base64UrlPayload, "changeme_MYSQL_PASSWORD", true);
        $base64UrlSignature = base64UrlEncode($base64UrlSignature);
        $JWT = $base64UrlHeader . '.' . $base64UrlPayload . '.' . $base64UrlSignature;
        setcookie("token", $JWT, time() + 3600, "/", "", false, true);
    } else {
        echo "Mauvais login ou mdp";
    }
}
?>