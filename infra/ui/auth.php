<?php

include('jwt.php');

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
        $JWT = createToken($user['username']);
        setcookie("token", $JWT, time() + 3600, "/", "", false, true);
        header('Location: '."changepasswd.php");
    } else {
        echo "Mauvais login ou mdp";
    }
}
?>