<?php
// Parámetros de conexión
$host = getenv('DB_HOST') ?: "newserversql.mysql.database.azure.com";
$username = getenv('DB_USER') ?: "jgil9"; // Nota: incluir @nombreServidor
$password = getenv('DB_PASSWORD') ?: "Papijaime123";
$dbname = getenv('DB_NAME') ?: "prueba";
$ssl_cert = "/home/site/wwwroot/BaltimoreCyberTrustRoot.crt.pem";

// Función para conectar usando SSL
function connectDB($host, $username, $password, $dbname, $ssl_cert) {
    $con = mysqli_init();
    
    if (!$con) {
        die('Error inicializando MySQLi');
    }
    
    mysqli_ssl_set($con, NULL, NULL, $ssl_cert, NULL, NULL);
    
    if (!mysqli_real_connect($con, $host, $username, $password, $dbname, 3306, NULL, MYSQLI_CLIENT_SSL)) {
        die('Error de conexión (SSL): ' . mysqli_connect_error());
    }
    
    return $con;
}

// Intentar conectar
$con = connectDB($host, $username, $password, $dbname, $ssl_cert);

echo "<h2>Conexión a la base de datos exitosa usando SSL ✅</h2>";

// Consultar usuarios
$query = "SELECT id, nombre, correo FROM usuarios";
$result = mysqli_query($con, $query);

if ($result && mysqli_num_rows($result) > 0) {
    echo "<table border='1' cellpadding='10'>";
    echo "<tr><th>ID</th><th>Nombre</th><th>Correo</th></tr>";
    while($row = mysqli_fetch_assoc($result)) {
        echo "<tr>";
        echo "<td>".htmlspecialchars($row['id'])."</td>";
        echo "<td>".htmlspecialchars($row['nombre'])."</td>";
        echo "<td>".htmlspecialchars($row['correo'])."</td>";
        echo "</tr>";
    }
    echo "</table>";
} else {
    echo "<p>No hay usuarios registrados.</p>";
}

mysqli_close($con);
?>
