<?php
// Activar errores visibles
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

echo "<h2>Validando conexión a bases de datos...</h2>";


// --- Función de conexión MySQL con SSL ---
function getMySqlConnection() {
    $host = "10.170.6.4";
    $user = "jgil9";
    $pass = "Papijaime123";
    $db   = "";
    $port = 3306;

    $con = mysqli_init();
    mysqli_ssl_set($con, NULL, NULL, NULL, NULL, NULL);
    mysqli_real_connect(
        $con,
        $host,
        $user,
        $pass,
        $db,
        $port,
        NULL,
        MYSQLI_CLIENT_SSL
    );

    if (mysqli_connect_errno()) {
        die("<div class='message error'>❌ Error MySQL (SSL): " . mysqli_connect_error() . "</div>");
    }
    return $con;
}

// --- Función de registro ---
function registerUser($nombre, $username, $password) {
    $con = getMySqlConnection();
    // Verificar existencia
    $stmt = $con->prepare("SELECT id FROM usuarios WHERE usuario = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();
    if ($stmt->num_rows > 0) {
        echo "<div class='message error'>❌ El usuario '{$username}' ya existe.</div>";
        $stmt->close();
        $con->close();
        return;
    }
    $stmt->close();
    // Insertar con hash
    $hash = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $con->prepare("INSERT INTO usuarios (nombre, usuario, contrasena) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $nombre, $username, $hash);
    if ($stmt->execute()) {
        echo "<div class='message success'>✅ Usuario '{$username}' registrado correctamente.</div>";
    } else {
        echo "<div class='message error'>❌ Error al registrar: " . $stmt->error . "</div>";
    }
    $stmt->close();
    $con->close();
}

// --- Función de login ---
function loginUser($username, $password) {
    $con = getMySqlConnection();
    // Obtener hash
    $stmt = $con->prepare("SELECT contrasena FROM usuarios WHERE usuario = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->bind_result($hash);
    if (!$stmt->fetch()) {
        echo "<div class='message error'>❌ Usuario '{$username}' no encontrado.</div>";
        $stmt->close();
        $con->close();
        return;
    }
    $stmt->close();
    // Verificar contraseña
    if (password_verify($password, $hash)) {
        echo "<div class='message success'>✅ Login exitoso. ¡Bienvenido, {$username}!</div>";
    } else {
        echo "<div class='message error'>❌ Contraseña incorrecta.</div>";
    }
    $con->close();
}

// --- Lógica de recepción de formulario ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action   = $_POST['action']   ?? '';
    $nombre   = trim($_POST['nombre']   ?? '');
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($action === 'register') {
        registerUser($nombre, $username, $password);
    } elseif ($action === 'login') {
        loginUser($username, $password);
    } else {
        echo "<div class='message error'>⚠ Acción inválida.</div>";
    }
    exit;
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Auth PHP en App Service</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background: #f0f2f5;
      margin: 0;
      padding: 20px;
    }
    .container {
      max-width: 400px;
      background: #fff;
      margin: 0 auto;
      padding: 20px;
      border-radius: 8px;
      box-shadow: 0 2px 6px rgba(0,0,0,0.1);
    }
    h2 {
      text-align: center;
      color: #333;
    }
    form {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    label {
      display: flex;
      flex-direction: column;
      color: #555;
    }
    input[type="text"],
    input[type="password"] {
      padding: 8px;
      border: 1px solid #ccc;
      border-radius: 4px;
    }
    button {
      padding: 10px;
      border: none;
      border-radius: 4px;
      background: #007bff;
      color: #fff;
      cursor: pointer;
      font-size: 16px;
    }
    button:hover {
      background: #0056b3;
    }
    hr {
      border: none;
      border-top: 1px solid #eee;
      margin: 20px 0;
    }
    .message {
      padding: 10px;
      border-radius: 4px;
      margin-bottom: 10px;
      font-weight: bold;
    }
    .message.success {
      background: #e6ffed;
      color: #2f6627;
    }
    .message.error {
      background: #ffe6e6;
      color: #a12f2f;
    }
  </style>
</head>
<body>
  <div class="container">
    <h2>Register</h2>
    <form method="post">
      <input type="hidden" name="action" value="register">
      <label>Nombre:
        <input type="text" name="nombre" required>
      </label>
      <label>Usuario:
        <input type="text" name="username" required>
      </label>
      <label>Contraseña:
        <input type="password" name="password" required>
      </label>
      <button type="submit">Registrar</button>
    </form>

    <hr>

    <h2>Login</h2>
    <form method="post">
      <input type="hidden" name="action" value="login">
      <label>Usuario:
        <input type="text" name="username" required>
      </label>
      <label>Contraseña:
        <input type="password" name="password" required>
      </label>
      <button type="submit">Entrar</button>
    </form>
  </div>
</body>
</html>