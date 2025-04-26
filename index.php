<?php
// Configuración de conexión
$host = "newserversql.mysql.database.azure.com";
$username = "jgil9@newserversql";  // ¡Formato requerido!
$password = "TuContraseñaSegura";
$dbname = "prueba";
$ssl_cert = "/home/site/wwwroot/BaltimoreCyberTrustRoot.crt.pem";

// Conexión con SSL forzado
try {
    $con = mysqli_init();
    
    // Configuración SSL crítica para Azure
    mysqli_ssl_set(
        $con,
        NULL,
        NULL,
        $ssl_cert,
        NULL,
        NULL
    );
    
    // Conexión real con parámetros explícitos
    mysqli_real_connect(
        $con,
        $host,
        $username,
        $password,
        $dbname,
        3306,
        NULL,
        MYSQLI_CLIENT_SSL
    );

    if ($con->connect_error) {
        throw new Exception("Error SSL: " . $con->connect_error);
    }

    // Consulta de ejemplo (usuarios registrados)
    $result = $con->query("SELECT * FROM usuarios");
    while($row = $result->fetch_assoc()) {
        echo "ID: ".$row['id']." - Nombre: ".$row['nombre']."<br>";
    }

} catch (Exception $e) {
    echo "<strong>Error mejorado:</strong> " . $e->getMessage();
    
    // Sugerencias específicas
    echo "<ol>
            <li>Verifica que el certificado SSL existe en $ssl_cert</li>
            <li>Confirma que el usuario incluye @nombreservidor</li>
            <li>Revisa las reglas de firewall en Azure Portal</li>
          </ol>";
}
?>