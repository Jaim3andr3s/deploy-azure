<?php
// Configuración de conexión segura
$host = getenv('DB_HOST') ?: "newserversql.mysql.database.azure.com";
$username = getenv('DB_USER') ?: "jgil9";  // ¡Asegúrate de incluir @nombreservidor!
$password = getenv('DB_PASSWORD') ?: "Papijaime123";
$dbname = getenv('DB_NAME') ?: "prueba";
$ssl_cert = "/home/site/wwwroot/BaltimoreCyberTrustRoot.crt.pem";

// Estilo CSS mejorado
echo '<style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    table { border-collapse: collapse; width: 100%; margin: 20px 0; }
    th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
    th { background-color: #0078d4; color: white; }
    tr:nth-child(even) { background-color: #f2f2f2; }
    .error { color: red; margin: 10px 0; }
    .login-form { max-width: 400px; margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
    input[type="text"], input[type="password"] { width: 100%; padding: 8px; margin: 5px 0 15px; }
    input[type="submit"] { background: #0078d4; color: white; border: none; padding: 10px 15px; cursor: pointer; }
</style>';

// Función para conexión segura
function connectDB() {
    global $host, $username, $password, $dbname, $ssl_cert;
    
    $con = mysqli_init();
    if (!mysqli_ssl_set($con, NULL, NULL, $ssl_cert, NULL, NULL)) {
        throw new Exception("Error configurando SSL");
    }
    
    if (!mysqli_real_connect($con, $host, $username, $password, $dbname, 3306, NULL, MYSQLI_CLIENT_SSL)) {
        throw new Exception("Error de conexión: " . mysqli_connect_error());
    }
    
    return $con;
}

// Procesar login
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['login'])) {
    try {
        $con = connectDB();
        $user = $_POST['username'];
        $pass = $_POST['password'];
        
        // Consulta preparada para seguridad
        $stmt = $con->prepare("SELECT * FROM usuarios WHERE nombre = ? AND contrasena = ?");
        $stmt->bind_param("ss", $user, $pass);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            echo "<p>¡Login exitoso! Bienvenido $user</p>";
            // Aquí podrías iniciar sesión con session_start()
        } else {
            echo "<p class='error'>Credenciales incorrectas</p>";
        }
        
        $stmt->close();
        $con->close();
    } catch (Exception $e) {
        echo "<p class='error'>Error: " . $e->getMessage() . "</p>";
    }
}

// Mostrar formulario de login
echo '<div class="login-form">
        <h2>Login</h2>
        <form method="post">
            Usuario: <input type="text" name="username" required><br>
            Contraseña: <input type="password" name="password" required><br>
            <input type="submit" name="login" value="Iniciar sesión">
        </form>
      </div>';

// Mostrar tabla de usuarios
try {
    $con = connectDB();
    $result = $con->query("SELECT id, nombre, correo FROM usuarios ORDER BY id DESC");
    
    echo '<h2>Usuarios Registrados</h2>';
    
    if ($result->num_rows > 0) {
        echo '<table>
                <tr><th>ID</th><th>Nombre</th><th>Correo</th></tr>';
        
        while($row = $result->fetch_assoc()) {
            echo '<tr>
                    <td>'.htmlspecialchars($row['id']).'</td>
                    <td>'.htmlspecialchars($row['nombre']).'</td>
                    <td>'.htmlspecialchars($row['correo']).'</td>
                  </tr>';
        }
        
        echo '</table>';
    } else {
        echo '<p>No hay usuarios registrados</p>';
    }
    
    $con->close();
} catch (Exception $e) {
    echo '<p class="error">Error al cargar usuarios: ' . $e->getMessage() . '</p>';
    
    // Mensaje de diagnóstico adicional
    echo '<div style="background:#f8f8f8;padding:10px;margin-top:20px;">
            <h4>Diagnóstico:</h4>
            <p>Ruta certificado SSL: '.$ssl_cert.'</p>
            <p>Usuario DB: '.$username.'</p>
            <p>Host DB: '.$host.'</p>
          </div>';
}
?>