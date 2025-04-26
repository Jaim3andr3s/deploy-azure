<?php
// Configuración de seguridad
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);

// Activar errores solo en desarrollo
if ($_SERVER['REMOTE_ADDR'] == '10.170.0.0') {
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
    error_reporting(E_ALL);
} else {
    error_reporting(0);
}

// --- Configuración de red ---
$allowed_ips = ['10.170.0.0/16', '10.167.0.0/16']; // Rangos permitidos
$client_ip = $_SERVER['REMOTE_ADDR'];

// Verificar IP
if (!ip_in_range($client_ip, $allowed_ips)) {
    die("<h2>Acceso no autorizado desde la IP: $client_ip</h2>");
}

// --- Conexión PostgreSQL (10.167.2.4) ---
function getPgConnection() {
    $config = [
        'host' => '10.167.2.4',
        'port' => '5432',
        'dbname' => 'postgres',
        'user' => 'rooot',
        'password' => 'Rut12345',
        'sslmode' => 'require'
    ];
    
    $conn_str = sprintf(
        "host=%s port=%s dbname=%s user=%s password=%s sslmode=%s",
        $config['host'],
        $config['port'],
        $config['dbname'],
        $config['user'],
        $config['password'],
        $config['sslmode']
    );
    
    $conn = pg_connect($conn_str);
    if (!$conn) {
        throw new Exception("PostgreSQL Error: " . pg_last_error());
    }
    return $conn;
}

// --- Conexión MySQL con SSL (10.167.0.4) ---
function getMySqlConnection() {
    $config = [
        'host' => '10.167.0.4',
        'user' => 'rooot',
        'pass' => 'Rut12345',
        'db'   => 'main',
        'port' => 3306,
        'ssl_cert' => '/home/site/wwwroot/BaltimoreCyberTrustRoot.crt.pem'
    ];
    
    $con = mysqli_init();
    mysqli_ssl_set($con, NULL, NULL, $config['ssl_cert'], NULL, NULL);
    
    if (!mysqli_real_connect(
        $con,
        $config['host'],
        $config['user'],
        $config['pass'],
        $config['db'],
        $config['port'],
        NULL,
        MYSQLI_CLIENT_SSL
    )) {
        throw new Exception("MySQL SSL Error: " . mysqli_connect_error());
    }
    return $con;
}

// --- Funciones de autenticación mejoradas ---
function registerUser($nombre, $username, $password) {
    if (strlen($password) < 8) {
        throw new Exception("La contraseña debe tener al menos 8 caracteres");
    }
    
    $con = getMySqlConnection();
    try {
        // Verificar existencia con consulta preparada
        $stmt = $con->prepare("SELECT id FROM usuarios WHERE usuario = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->store_result();
        
        if ($stmt->num_rows > 0) {
            throw new Exception("El usuario ya existe");
        }
        
        // Insertar con hash seguro
        $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
        $stmt = $con->prepare("INSERT INTO usuarios (nombre, usuario, contrasena) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $nombre, $username, $hash);
        
        if (!$stmt->execute()) {
            throw new Exception("Error al registrar: " . $stmt->error);
        }
        
        return true;
    } finally {
        $stmt->close();
        $con->close();
    }
}

function loginUser($username, $password) {
    $con = getMySqlConnection();
    try {
        $stmt = $con->prepare("SELECT id, contrasena FROM usuarios WHERE usuario = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->bind_result($id, $hash);
        
        if (!$stmt->fetch()) {
            throw new Exception("Usuario no encontrado");
        }
        
        if (!password_verify($password, $hash)) {
            throw new Exception("Contraseña incorrecta");
        }
        
        // Iniciar sesión segura
        session_start();
        session_regenerate_id(true);
        $_SESSION['user_id'] = $id;
        $_SESSION['ip'] = $_SERVER['REMOTE_ADDR'];
        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
        
        return true;
    } finally {
        $stmt->close();
        $con->close();
    }
}

// --- Helper para rangos IP ---
function ip_in_range($ip, $ranges) {
    foreach ($ranges as $range) {
        list($subnet, $mask) = explode('/', $range);
        if ((ip2long($ip) & ~((1 << (32 - $mask)) - 1)) == ip2long($subnet)) {
            return true;
        }
    }
    return false;
}

// --- Procesamiento del formulario ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $action = $_POST['action'] ?? '';
        $nombre = trim($_POST['nombre'] ?? '');
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        
        if ($action === 'register') {
            registerUser($nombre, $username, $password);
            $message = "✅ Registro exitoso. Ahora puedes iniciar sesión.";
        } elseif ($action === 'login') {
            loginUser($username, $password);
            $message = "✅ Inicio de sesión exitoso. Redirigiendo...";
            // header("Location: dashboard.php");
            // exit;
        }
    } catch (Exception $e) {
        $message = "❌ Error: " . $e->getMessage();
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sistema de Autenticación Segura</title>
  <style>
    :root {
      --primary: #0078d4;
      --error: #d13438;
      --success: #107c10;
    }
    body {
      font-family: 'Segoe UI', Arial, sans-serif;
      background: #f3f2f1;
      margin: 0;
      padding: 20px;
      color: #323130;
    }
    .container {
      max-width: 440px;
      margin: 40px auto;
      background: #fff;
      border-radius: 4px;
      box-shadow: 0 1.6px 3.6px rgba(0,0,0,.13), 0 0.3px 0.9px rgba(0,0,0,.11);
      overflow: hidden;
    }
    .form-header {
      background: var(--primary);
      color: white;
      padding: 16px 24px;
    }
    .form-body {
      padding: 24px;
    }
    .form-group {
      margin-bottom: 16px;
    }
    label {
      display: block;
      margin-bottom: 4px;
      font-weight: 600;
    }
    input[type="text"],
    input[type="password"] {
      width: 100%;
      padding: 8px 12px;
      border: 1px solid #edebe9;
      border-radius: 2px;
      font-size: 14px;
    }
    button {
      background: var(--primary);
      color: white;
      border: none;
      padding: 8px 16px;
      border-radius: 2px;
      cursor: pointer;
      font-weight: 600;
    }
    .message {
      padding: 12px;
      margin-bottom: 20px;
      border-radius: 2px;
      border-left: 4px solid;
    }
    .message-error {
      background: #fdf6f6;
      border-color: var(--error);
      color: var(--error);
    }
    .message-success {
      background: #f1faf1;
      border-color: var(--success);
      color: var(--success);
    }
    .tabs {
      display: flex;
      border-bottom: 1px solid #edebe9;
    }
    .tab {
      padding: 12px 16px;
      cursor: pointer;
    }
    .tab.active {
      border-bottom: 2px solid var(--primary);
      font-weight: 600;
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
  <div class="container">
    <div class="form-header">
      <h2>Sistema de Autenticación</h2>
      <p>Acceso seguro para redes autorizadas (10.170.0.0/16)</p>
    </div>
    
    <?php if (!empty($message)): ?>
      <div class="message <?= strpos($message, '✅') !== false ? 'message-success' : 'message-error' ?>">
        <?= $message ?>
      </div>
    <?php endif; ?>
    
    <div class="tabs">
      <div class="tab active" onclick="switchTab('login')">Iniciar Sesión</div>
      <div class="tab" onclick="switchTab('register')">Registrarse</div>
    </div>
    
    <div class="form-body">
      <div id="login-tab" class="tab-content active">
        <form method="post">
          <input type="hidden" name="action" value="login">
          <div class="form-group">
            <label for="login-username">Usuario</label>
            <input type="text" id="login-username" name="username" required>
          </div>
          <div class="form-group">
            <label for="login-password">Contraseña</label>
            <input type="password" id="login-password" name="password" required>
          </div>
          <button type="submit">Entrar</button>
        </form>
      </div>
      
      <div id="register-tab" class="tab-content">
        <form method="post">
          <input type="hidden" name="action" value="register">
          <div class="form-group">
            <label for="reg-name">Nombre Completo</label>
            <input type="text" id="reg-name" name="nombre" required>
          </div>
          <div class="form-group">
            <label for="reg-username">Usuario</label>
            <input type="text" id="reg-username" name="username" required>
          </div>
          <div class="form-group">
            <label for="reg-password">Contraseña (mínimo 8 caracteres)</label>
            <input type="password" id="reg-password" name="password" required minlength="8">
          </div>
          <button type="submit">Registrarse</button>
        </form>
      </div>
    </div>
  </div>

  <script>
    function switchTab(tabName) {
      // Ocultar todos los contenidos
      document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
      });
      
      // Mostrar el seleccionado
      document.getElementById(tabName + '-tab').classList.add('active');
      
      // Actualizar pestañas activas
      document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.remove('active');
      });
      event.currentTarget.classList.add('active');
    }
  </script>
</body>
</html>