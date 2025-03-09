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

    if (isset($_POST['new_password'])) {
        $new_password = htmlspecialchars($_POST['new_password']);
        $hash_new_password = password_hash($new_password, PASSWORD_DEFAULT);
        $sql = "UPDATE ui_users SET pass = (?) WHERE username = 'admin'";
        $stmt= $pdo->prepare($sql);
        $stmt->execute([$hash_new_password]);
        header('Location: '."index.php");
    }
}else{
    header('Location: '."login.php");
}

?>

<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8">
		<title>Change passwd</title>
	</head>
	<body>
		<div class="login">
			<h1>Change admin password</h1>
			<form action="" method="post">
				<input type="new_password" name="new_password" placeholder="new password" id="new_password" required>
				<input type="submit" value="Change admin password">
			</form>
		</div>
	</body>
</html>