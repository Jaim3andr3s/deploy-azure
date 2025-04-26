<?php
$host = "newserversql.mysql.database.azure.com";
$username = "jgil9";  // ¡Formato requerido!
$password = "Papijaime123";
$dbname = "prueba";
$ssl_cert = "/home/site/wwwroot/BaltimoreCyberTrustRoot.crt.pem";

$con = mysqli_init();
mysqli_ssl_set($con, NULL, NULL, $ssl_cert, NULL, NULL);
mysqli_real_connect($con, $host, $username, $password, $dbname, 3306, NULL, MYSQLI_CLIENT_SSL);

if ($con->connect_error) {
    die("Error de conexión SSL: " . $con->connect_error);
}
echo "¡Conexión exitosa!";
?>