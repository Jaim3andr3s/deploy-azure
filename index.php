<?php
// Activar errores visibles
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

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
        die("<div class='alert error'>❌ Error MySQL (SSL): " . mysqli_connect_error() . "</div>");
    }
    return $con;
}

// --- Funciones de autenticación ---
function registerUser($nombre, $username, $password) {
    $con = getMySqlConnection();
    
    $stmt = $con->prepare("SELECT id FROM usuarios WHERE usuario = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();
    
    if ($stmt->num_rows > 0) {
        echo "<div class='alert error'>El usuario ya existe</div>";
        return;
    }
    
    $hash = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $con->prepare("INSERT INTO usuarios (nombre, usuario, contrasena) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $nombre, $username, $hash);
    
    if ($stmt->execute()) {
        echo "<div class='alert success'>Registro exitoso</div>";
    } else {
        echo "<div class='alert error'>Error al registrar: " . $stmt->error . "</div>";
    }
    
    $stmt->close();
    $con->close();
}

function loginUser($username, $password) {
    $con = getMySqlConnection();
    
    $stmt = $con->prepare("SELECT contrasena FROM usuarios WHERE usuario = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->bind_result($hash);
    
    if (!$stmt->fetch()) {
        echo "<div class='alert error'>Usuario no encontrado</div>";
        return;
    }
    
    if (password_verify($password, $hash)) {
        echo "<div class='alert success'>Bienvenido, $username</div>";
        // Aquí podrías iniciar sesión
    } else {
        echo "<div class='alert error'>Contraseña incorrecta</div>";
    }
    
    $stmt->close();
    $con->close();
}

// --- Manejo del formulario ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $nombre = trim($_POST['nombre'] ?? '');
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    
    if ($action === 'register') {
        registerUser($nombre, $username, $password);
    } elseif ($action === 'login') {
        loginUser($username, $password);
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sistema de Autenticación</title>
  <style>
    :root {
      --primary: #4361ee;
      --success: #2ecc71;
      --error: #e74c3c;
      --dark: #2c3e50;
      --light: #ecf0f1;
      --gray: #95a5a6;
    }
    
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    
    body {
      background-color: #f5f7fa;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      padding: 20px;
    }
    
    .auth-container {
      width: 100%;
      max-width: 420px;
      background: white;
      border-radius: 12px;
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.08);
      overflow: hidden;
    }
    
    .auth-header {
      background: var(--primary);
      color: white;
      padding: 20px;
      text-align: center;
    }
    
    .auth-header h1 {
      font-size: 1.8rem;
      font-weight: 600;
    }
    
    .auth-tabs {
      display: flex;
      border-bottom: 1px solid #eee;
    }
    
    .auth-tab {
      flex: 1;
      padding: 15px;
      text-align: center;
      cursor: pointer;
      font-weight: 500;
      color: var(--gray);
      transition: all 0.3s;
    }
    
    .auth-tab.active {
      color: var(--primary);
      border-bottom: 2px solid var(--primary);
    }
    
    .auth-content {
      padding: 25px;
    }
    
    .auth-form {
      display: flex;
      flex-direction: column;
      gap: 20px;
    }
    
    .form-group {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    
    .form-group label {
      font-size: 0.9rem;
      color: var(--dark);
      font-weight: 500;
    }
    
    .form-group input {
      padding: 12px 15px;
      border: 1px solid #ddd;
      border-radius: 8px;
      font-size: 1rem;
      transition: border 0.3s;
    }
    
    .form-group input:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(67, 97, 238, 0.2);
    }
    
    .auth-btn {
      background: var(--primary);
      color: white;
      border: none;
      padding: 14px;
      border-radius: 8px;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.3s;
    }
    
    .auth-btn:hover {
      background: #3a56d4;
    }
    
    .divider {
      display: flex;
      align-items: center;
      margin: 20px 0;
      color: var(--gray);
      font-size: 0.9rem;
    }
    
    .divider::before, .divider::after {
      content: "";
      flex: 1;
      border-bottom: 1px solid #eee;
    }
    
    .divider::before {
      margin-right: 10px;
    }
    
    .divider::after {
      margin-left: 10px;
    }
    
    .alert {
      padding: 12px 15px;
      border-radius: 8px;
      margin-bottom: 20px;
      font-size: 0.9rem;
      display: flex;
      align-items: center;
    }
    
    .alert.success {
      background: rgba(46, 204, 113, 0.1);
      color: var(--success);
      border-left: 4px solid var(--success);
    }
    
    .alert.error {
      background: rgba(231, 76, 60, 0.1);
      color: var(--error);
      border-left: 4px solid var(--error);
    }
    
    .tab-content {
      display: none;
    }
    
    .tab-content.active {
      display: block;
    }
  </style>
</head>
<body>
  <div class="auth-container">
    <div class="auth-header">
      <h1>Sistema de Autenticación</h1>
    </div>
    
    <div class="auth-tabs">
      <div class="auth-tab active" onclick="switchTab('register')">Registro</div>
      <div class="auth-tab" onclick="switchTab('login')">Iniciar Sesión</div>
    </div>
    
    <div class="auth-content">
      <!-- Mensajes de feedback -->
      <?php if (isset($_POST['action'])): ?>
        <div class="alert <?= strpos($_POST['action'], 'error') ? 'error' : 'success' ?>">
          <?= $message ?? '' ?>
        </div>
      <?php endif; ?>
      
      <!-- Formulario de Registro -->
      <div id="register-tab" class="tab-content active">
        <form method="post" class="auth-form">
          <input type="hidden" name="action" value="register">
          
          <div class="form-group">
            <label for="nombre">Nombre Completo</label>
            <input type="text" id="nombre" name="nombre" required>
          </div>
          
          <div class="form-group">
            <label for="username">Usuario</label>
            <input type="text" id="username" name="username" required>
          </div>
          
          <div class="form-group">
            <label for="password">Contraseña</label>
            <input type="password" id="password" name="password" required>
          </div>
          
          <button type="submit" class="auth-btn">Registrarse</button>
        </form>
      </div>
      
      <!-- Formulario de Login -->
      <div id="login-tab" class="tab-content">
        <form method="post" class="auth-form">
          <input type="hidden" name="action" value="login">
          
          <div class="form-group">
            <label for="login-username">Usuario</label>
            <input type="text" id="login-username" name="username" required>
          </div>
          
          <div class="form-group">
            <label for="login-password">Contraseña</label>
            <input type="password" id="login-password" name="password" required>
          </div>
          
          <button type="submit" class="auth-btn">Iniciar Sesión</button>
        </form>
      </div>
    </div>
  </div>

  <script>
    function switchTab(tabName) {
      // Cambiar pestañas activas
      document.querySelectorAll('.auth-tab').forEach(tab => {
        tab.classList.remove('active');
      });
      document.querySelector(`.auth-tab[onclick="switchTab('${tabName}')"]`).classList.add('active');
      
      // Cambiar contenido visible
      document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
      });
      document.getElementById(`${tabName}-tab`).classList.add('active');
    }
  </script>
</body>
</html>