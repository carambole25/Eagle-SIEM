<?php

include('jwt.php');

if (isset($_COOKIE['token']) && validateToken($_COOKIE['token'])){
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

    if (isset($_GET['key'])) {
        $generated_key = htmlspecialchars($_GET['key']);
        $sql = "INSERT INTO api_keys (api_key) VALUES (?)";
        $stmt= $pdo->prepare($sql);
        $stmt->execute([$generated_key]);
        echo $generated_key;
    }
}

?>

<!DOCTYPE html>
<html lang="fr">
    <head>
        <meta charset="utf-8">
        <title>Titre de la page</title>
        <link rel="stylesheet" href="style.css">
        <script src="script.js"></script>
    </head>
    <body>
        <a id="api_key" href="">Get api key</a>
    </body>
</html>

<script type="text/javascript">
    let api_key = Math.random().toString(36).substr(2, 10)+Math.random().toString(36).substr(2, 10);
    document.getElementById("api_key").href="generate_api_key.php?key="+api_key; 
</script>
