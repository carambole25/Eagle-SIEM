<?php

if (isset($_POST['username']) &&  isset($_POST['password'])) {
    $host = 'db';
    $dbname = 'eagle_db';
    $username = 'MYSQL_USER';
    $password = 'MYSQL_PASSWORD';

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
        echo "Connexion OK !";
        $_SESSION['user'] = $user;
    } else {
        echo "Mauvais login ou mdp";
    }
}
?>