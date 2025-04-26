<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aplicación PHP + MySQL en Azure</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; margin: 0 auto; max-width: 800px; padding: 20px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
        th { background-color: #f2f2f2; }
        form { background: #f9f9f9; padding: 20px; border-radius: 5px; }
        input[type="text"] { width: 100%; padding: 8px; margin: 5px 0 15px; }
        input[type="submit"] { background: #0078d4; color: white; border: none; padding: 10px 15px; cursor: pointer; }
        .success { color: green; margin: 10px 0; }
        .error { color: red; }
    </style>
</head>
<body>
    <h1>Registro de Usuarios</h1>
    
    <?php
    // Configuración de conexión (mejor usar variables de entorno en producción)
    $host = getenv('DB_HOST') ?: "newserversql.mysql.database.azure.com";
    $username = getenv('DB_USER') ?: "Jgil9@newserversql";
    $password = getenv('DB_PASSWORD') ?: "Papijaime123";
    $dbname = getenv('DB_NAME') ?: "prueba";

    // Manejar el formulario de inserción
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        try {
            $con = mysqli_init();
            mysqli_ssl_set($con, NULL, NULL, "/var/www/html/BaltimoreCyberTrustRoot.crt.pem", NULL, NULL);
            mysqli_real_connect($con, $host, $username, $password, $dbname, 3306, NULL, MYSQLI_CLIENT_SSL);

            $nombre = htmlspecialchars($_POST['nombre']);
            $correo = htmlspecialchars($_POST['correo']);

            $stmt = $con->prepare("INSERT INTO usuarios (nombre, correo) VALUES (?, ?)");
            $stmt->bind_param("ss", $nombre, $correo);
            
            if ($stmt->execute()) {
                echo "<p class='success'>Usuario agregado correctamente.</p>";
            } else {
                echo "<p class='error'>Error al agregar usuario: " . $con->error . "</p>";
            }
            
            $stmt->close();
            $con->close();
        } catch (Exception $e) {
            echo "<p class='error'>Error de conexión: " . $e->getMessage() . "</p>";
        }
    }
    ?>

    <!-- Formulario para agregar usuarios -->
    <form method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
        <label for="nombre">Nombre:</label>
        <input type="text" id="nombre" name="nombre" required>
        
        <label for="correo">Correo electrónico:</label>
        <input type="text" id="correo" name="correo" required>
        
        <input type="submit" value="Registrar Usuario">
    </form>

    <!-- Lista de usuarios registrados -->
    <h2>Usuarios Registrados</h2>
    <?php
    try {
        $con = mysqli_init();
        mysqli_ssl_set($con, NULL, NULL, "/var/www/html/BaltimoreCyberTrustRoot.crt.pem", NULL, NULL);
        mysqli_real_connect($con, $host, $username, $password, $dbname, 3306, NULL, MYSQLI_CLIENT_SSL);

        $result = $con->query("SELECT id, nombre, correo FROM usuarios ORDER BY id DESC");

        if ($result->num_rows > 0) {
            echo "<table>
                <tr><th>ID</th><th>Nombre</th><th>Correo</th></tr>";
            
            while($row = $result->fetch_assoc()) {
                echo "<tr>
                    <td>" . htmlspecialchars($row['id']) . "</td>
                    <td>" . htmlspecialchars($row['nombre']) . "</td>
                    <td>" . htmlspecialchars($row['correo']) . "</td>
                </tr>";
            }
            
            echo "</table>";
        } else {
            echo "<p>No hay usuarios registrados aún.</p>";
        }

        $con->close();
    } catch (Exception $e) {
        echo "<p class='error'>Error al cargar usuarios: " . $e->getMessage() . "</p>";
    }
    ?>
</body>
</html>