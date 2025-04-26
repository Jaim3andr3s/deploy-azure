<?php
header('Content-Type: text/plain; charset=utf-8');

echo "=== Prueba de conexión a Azure MySQL ===\n\n";

// Configuración (usa variables de entorno en producción)
$host = getenv('DB_HOST') ?: "newserversql.mysql.database.azure.com";
$username = getenv('DB_USER') ?: "Jgil9";
$password = getenv('DB_PASSWORD') ?: "Papijaime123";
$dbname = getenv('DB_NAME') ?: "prueba";

try {
    echo "🔹 Intentando conexión...\n";
    $con = mysqli_init();
    
    // Configuración SSL obligatoria para Azure MySQL
    mysqli_ssl_set($con, NULL, NULL, "/var/www/html/BaltimoreCyberTrustRoot.crt.pem", NULL, NULL);
    
    echo "🔹 Conectando a: $host...\n";
    mysqli_real_connect($con, $host, $username, $password, $dbname, 3306, NULL, MYSQLI_CLIENT_SSL);
    
    if ($con->connect_error) {
        throw new Exception("Conexión fallida: " . $con->connect_error);
    }
    
    echo "✅ ¡Conexión exitosa!\n\n";
    echo "🔹 Información del servidor:\n";
    echo "   - Versión MySQL: " . $con->server_info . "\n";
    echo "   - Host: " . $con->host_info . "\n";
    echo "   - Protocolo: " . $con->protocol_version . "\n";
    
    // Prueba de consulta
    echo "\n🔹 Probando consulta a la tabla 'usuarios'...\n";
    $result = $con->query("SELECT COUNT(*) AS total FROM usuarios");
    $row = $result->fetch_assoc();
    echo "   - Total de usuarios: " . $row['total'] . "\n";
    
    $con->close();
} catch (Exception $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
    
    // Sugerencias para depuración
    echo "\n🔧 Posibles soluciones:\n";
    echo "1. Verifica que el servidor MySQL permita conexiones desde Azure Web App (firewall)\n";
    echo "2. Revisa el formato del usuario: debe ser 'usuario@nombreservidor'\n";
    echo "3. Asegúrate de que la BD y tabla existen\n";
    echo "4. Comprueba que el certificado SSL esté en '/var/www/html/BaltimoreCyberTrustRoot.crt.pem'\n";
}

echo "\n=== Fin de la prueba ===";
?>