<?php
// Configuración básica
$host = 'newserversql.mysql.database.azure.com';
$user = 'jgil9@newserversql';  // Asegúrate de incluir @nombreservidor
$pass = 'Papijaime123';
$db = 'prueba';
$ssl_cert = '/home/site/wwwroot/BaltimoreCyberTrustRoot.crt.pem';

// Intento de conexión
try {
    $con = mysqli_init();
    
    // Configuración SSL
    mysqli_ssl_set($con, NULL, NULL, $ssl_cert, NULL, NULL);
    
    // Conexión real
    if (!mysqli_real_connect($con, $host, $user, $pass, $db, 3306, NULL, MYSQLI_CLIENT_SSL)) {
        throw new Exception("Error de conexión: " . mysqli_connect_error());
    }

    // Prueba simple de consulta
    $result = $con->query("SHOW TABLES");
    if (!$result) {
        throw new Exception("Error en consulta: " . $con->error);
    }

    echo "<h2>Conexión exitosa a MySQL</h2>";
    echo "<p>Host: $host</p>";
    echo "<p>Usuario: $user</p>";
    echo "<p>Base de datos: $db</p>";
    
    echo "<h3>Tablas encontradas:</h3>";
    echo "<ul>";
    while ($row = $result->fetch_row()) {
        echo "<li>" . htmlspecialchars($row[0]) . "</li>";
    }
    echo "</ul>";

    $con->close();
    
} catch (Exception $e) {
    echo "<h2>Error de conexión</h2>";
    echo "<p><strong>Mensaje:</strong> " . htmlspecialchars($e->getMessage()) . "</p>";
    echo "<p><strong>Certificado SSL:</strong> " . (file_exists($ssl_cert) ? "Encontrado en $ssl_cert" : "NO encontrado") . "</p>";
}
?>