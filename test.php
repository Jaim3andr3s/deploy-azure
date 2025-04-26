<?php
$con = mysqli_init();
mysqli_ssl_set($con, NULL, NULL, "/home/site/wwwroot/BaltimoreCyberTrustRoot.crt.pem", NULL, NULL);
if (mysqli_real_connect($con, "[host]", "[usuario]", "[contraseña]", "[bd]", 3306, NULL, MYSQLI_CLIENT_SSL)) {
    echo "SSL OK!";
} else {
    echo "SSL Falló: " . mysqli_connect_error();
}
?>