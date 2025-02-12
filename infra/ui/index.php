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

    # ça ressemble à un injection sql mais c'est volontaire
    # l'utilisateur peu query la bdd
    # faudra à l'avenir faire en sorte qu'il puisse que consulter les données (readonly) et que events pas apikey
    if (isset($_GET['save'])){
        $sql = "INSERT INTO `save_query`(`query`) VALUES (?)";
        $stmt= $pdo->prepare($sql);
        $stmt->execute([$_GET['query']]);
    } else {
        if (isset($_GET['query'])){
            $query = $_GET['query']; 
        } else {
            $query = "SELECT * FROM `events`";
        }
        $sql = $query;
        $stmt = $pdo->prepare($sql);
        $stmt->execute();
        $results = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($results) {
            echo "<table border='1'>";
            echo "<tr>";
            foreach (array_keys($results[0]) as $header) {
                echo "<th>" . htmlspecialchars($header) . "</th>";
            }
            echo "</tr>";

            foreach ($results as $row) {
                echo "<tr>";
                foreach ($row as $value) {
                    echo "<td>" . htmlspecialchars($value) . "</td>";
                }
                echo "</tr>";
            }
            echo "</table>";
        }
    }
}else{
    header('Location: '."login.php");
}

?>

<!DOCTYPE html>
<html lang="fr">
    <head>
        <meta charset="utf-8">
        <title>Titre de la page</title>
        <link rel="stylesheet" href="style.css">
        <script src="script.js"></script>
        <link rel="stylesheet" type="text/css" href="style_index.css">
    </head>
    <body>
        <br>
        <form action="" method="get">
        <label for="query">Query to bdd :</label><br>
        <textarea id="query" name="query" rows="10" cols="50"></textarea><br>
        <br>
        <label for="save">Save ?</label><input type="checkbox" id="save" name="save"/>
        <button type="submit">Submit/Save</button>
        </form>

        <div id='liste_saved_query'>
        <?php
            $sql = "SELECT query FROM `save_query`";
            $stmt = $pdo->prepare($sql);
            $stmt->execute();
            $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
            echo "Query sauvegardé :<br>";
            foreach ($results as $row) {
                foreach ($row as $value) {
                    echo "<a href=/?query=". urlencode($value) . ">". htmlspecialchars($value) ."</a>";
                }
            }
        ?>
        <div>

        <br>
        <br>

        <a href="generate_api_key.php">Generer des clés API</a>
        
        <br>
        <br>

        <h1>Récupérer les agents : wget http://srv_ip/agent_linux.zip</h1>
    </body>
</html>

<script>
    // récupérer la var depuis le php
    // Les pip successif permet de netoyer l'entré pour éviter les xss et autres problèmes
    const currentQuery = <?php echo json_encode($query, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT); ?>;
    console.log(currentQuery);
    document.getElementById('query').value = currentQuery;
    document.getElementById('tosave').value = currentQuery;
</script>