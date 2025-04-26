<?php
// =============================================
// CONFIGURACIÓN PRINCIPAL
// =============================================

// IPs autorizadas (incluyendo la tuya 10.170.0.0 y otras necesarias)
$allowed_ips = [
    '10.170.0.0/16',    // Tu red principal
    '10.167.0.0/16',    // Red de la base de datos
    '169.254.130.1',    // IP que apareció en el error (probablemente interna de Azure)
    '127.0.0.1'         // Localhost para desarrollo
];

// Configuración de bases de datos
$db_config = [
    'mysql' => [
        'host' => 'newserversql.mysql.database.azure.com',
        'user' => 'Jgil9@newserversql',  // ¡Formato requerido con @servidor!
        'pass' => 'Papijaime123',
        'db' => 'prueba',
        'ssl_cert' => '/home/site/wwwroot/BaltimoreCyberTrustRoot.crt.pem'
    ],
    'postgres' => [
        'host' => '10.167.2.4',
        'port' => '5432',
        'dbname' => 'postgres',
        'user' => 'rooot',
        'pass' => 'Rut12345'
    ]
];

// =============================================
// FUNCIONES DE SEGURIDAD
// =============================================

// Función para verificar IPs
function is_ip_authorized($ip, $ranges) {
    foreach ($ranges as $range) {
        if (strpos($range, '/') !== false) {
            // Es un rango CIDR
            list($subnet, $mask) = explode('/', $range);
            $ip_long = ip2long($ip);
            $subnet_long = ip2long($subnet);
            $mask_long = ~((1 << (32 - $mask)) - 1);
            
            if (($ip_long & $mask_long) == ($subnet_long & $mask_long)) {
                return true;
            }
        } else {
            // IP individual
            if ($ip === $range) {
                return true;
            }
        }
    }
    return false;
}

// Función para registrar intentos de acceso no autorizados
function log_unauthorized_access($ip) {
    $log_entry = date('Y-m-d H:i:s') . " - Intento de acceso no autorizado desde IP: $ip\n";
    file_put_contents('/home/site/wwwroot/security.log', $log_entry, FILE_APPEND);
}

// =============================================
// MANEJO DE CONEXIONES
// =============================================

// Conexión MySQL con SSL
function get_mysql_connection() {
    global $db_config;
    
    $con = mysqli_init();
    mysqli_ssl_set(
        $con,
        NULL,
        NULL,
        $db_config['mysql']['ssl_cert'],
        NULL,
        NULL
    );
    
    $connected = mysqli_real_connect(
        $con,
        $db_config['mysql']['host'],
        $db_config['mysql']['user'],
        $db_config['mysql']['pass'],
        $db_config['mysql']['db'],
        3306,
        NULL,
        MYSQLI_CLIENT_SSL
    );
    
    if (!$connected) {
        throw new Exception("Error MySQL SSL: " . mysqli_connect_error());
    }
    
    return $con;
}

// Conexión PostgreSQL
function get_postgres_connection() {
    global $db_config;
    
    $conn_str = sprintf(
        "host=%s port=%s dbname=%s user=%s password=%s sslmode=require",
        $db_config['postgres']['host'],
        $db_config['postgres']['port'],
        $db_config['postgres']['dbname'],
        $db_config['postgres']['user'],
        $db_config['postgres']['pass']
    );
    
    $conn = pg_connect($conn_str);
    if (!$conn) {
        throw new Exception("Error PostgreSQL: " . pg_last_error());
    }
    
    return $conn;
}

// =============================================
// FUNCIONES DE AUTENTICACIÓN
// =============================================

function register_user($name, $username, $password) {
    if (strlen($password) < 8) {
        throw new Exception("La contraseña debe tener al menos 8 caracteres");
    }
    
    $con = get_mysql_connection();
    
    try {
        // Verificar si el usuario ya existe
        $stmt = $con->prepare("SELECT id FROM usuarios WHERE usuario = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->store_result();
        
        if ($stmt->num_rows > 0) {
            throw new Exception("El nombre de usuario ya está en uso");
        }
        
        // Crear hash seguro de la contraseña
        $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
        
        // Insertar nuevo usuario
        $stmt = $con->prepare("INSERT INTO usuarios (nombre, usuario, contrasena) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $name, $username, $hash);
        
        if (!$stmt->execute()) {
            throw new Exception("Error al registrar usuario: " . $stmt->error);
        }
        
        return true;
    } finally {
        $stmt->close();
        $con->close();
    }
}

function login_user($username, $password) {
    $con = get_mysql_connection();
    
    try {
        // Buscar usuario
        $stmt = $con->prepare("SELECT id, contrasena FROM usuarios WHERE usuario = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->bind_result($user_id, $stored_hash);
        
        if (!$stmt->fetch()) {
            throw new Exception("Usuario no encontrado");
        }
        
        // Verificar contraseña
        if (!password_verify($password, $stored_hash)) {
            throw new Exception("Contraseña incorrecta");
        }
        
        // Iniciar sesión segura
        session_start();
        session_regenerate_id(true);
        
        $_SESSION = [
            'user_id' => $user_id,
            'username' => $username,
            'ip' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT'],
            'last_activity' => time()
        ];
        
        return true;
    } finally {
        $stmt->close();
        $con->close();
    }
}

// =============================================
// VERIFICACIÓN INICIAL DE SEGURIDAD
// =============================================

// Obtener IP real del cliente (considerando proxies)
$client_ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];

// Verificar IP autorizada
if (!is_ip_authorized($client_ip, $allowed_ips)) {
    log_unauthorized_access($client_ip);
    die("<h2>Acceso no autorizado desde la IP: $client_ip</h2>");
}

// Configuración de seguridad de sesión
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_strict_mode', 1);

// =============================================
// MANEJO DE PETICIONES
// =============================================

$action = $_POST['action'] ?? '';
$response = [];

try {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        switch ($action) {
            case 'register':
                $name = trim($_POST['name'] ?? '');
                $username = trim($_POST['username'] ?? '');
                $password = $_POST['password'] ?? '';
                
                if (register_user($name, $username, $password)) {
                    $response = [
                        'status' => 'success',
                        'message' => 'Usuario registrado exitosamente'
                    ];
                }
                break;
                
            case 'login':
                $username = trim($_POST['username'] ?? '');
                $password = $_POST['password'] ?? '';
                
                if (login_user($username, $password)) {
                    $response = [
                        'status' => 'success',
                        'message' => 'Inicio de sesión exitoso',
                        'redirect' => 'dashboard.php'
                    ];
                }
                break;
                
            default:
                throw new Exception("Acción no válida");
        }
    }
} catch (Exception $e) {
    $response = [
        'status' => 'error',
        'message' => $e->getMessage()
    ];
}

// =============================================
// INTERFAZ DE USUARIO
// =============================================
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
            --warning: #ffaa44;
        }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background-color: #f3f2f1;
            margin: 0;
            padding: 0;
            color: #323130;
            line-height: 1.5;
        }
        .container {
            max-width: 440px;
            margin: 40px auto;
            background: #ffffff;
            border-radius: 4px;
            box-shadow: 0 1.6px 3.6px rgba(0,0,0,.13), 0 0.3px 0.9px rgba(0,0,0,.11);
            overflow: hidden;
        }
        .header {
            background: var(--primary);
            color: white;
            padding: 16px 24px;
        }
        .header h1 {
            margin: 0;
            font-size: 21px;
            font-weight: 600;
        }
        .header p {
            margin: 4px 0 0;
            font-size: 14px;
            opacity: 0.9;
        }
        .form-container {
            padding: 24px;
        }
        .tabs {
            display: flex;
            border-bottom: 1px solid #edebe9;
        }
        .tab {
            padding: 12px 16px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            color: #605e5c;
        }
        .tab.active {
            color: var(--primary);
            border-bottom: 2px solid var(--primary);
        }
        .tab-content {
            display: none;
            padding: 16px 0;
        }
        .tab-content.active {
            display: block;
        }
        .form-group {
            margin-bottom: 16px;
        }
        label {
            display: block;
            margin-bottom: 4px;
            font-size: 14px;
            font-weight: 600;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 8px 12px;
            border: 1px solid #edebe9;
            border-radius: 2px;
            font-size: 14px;
            box-sizing: border-box;
        }
        input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 2px rgba(0,120,212,0.1);
        }
        button {
            background: var(--primary);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 2px;
            cursor: pointer;
            font-weight: 600;
            font-size: 14px;
            width: 100%;
        }
        button:hover {
            background: #106ebe;
        }
        .alert {
            padding: 12px;
            margin-bottom: 16px;
            border-radius: 2px;
            border-left: 4px solid;
            font-size: 14px;
        }
        .alert-success {
            background: #f1faf1;
            border-color: var(--success);
            color: var(--success);
        }
        .alert-error {
            background: #fdf6f6;
            border-color: var(--error);
            color: var(--error);
        }
        .alert-warning {
            background: #fff4ce;
            border-color: var(--warning);
            color: #8a5000;
        }
        .ip-info {
            font-size: 12px;
            color: #605e5c;
            margin-top: 16px;
            padding-top: 16px;
            border-top: 1px solid #edebe9;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Sistema de Autenticación Segura</h1>
            <p>Acceso restringido a redes autorizadas</p>
        </div>
        
        <?php if (!empty($response)): ?>
            <div class="alert alert-<?= $response['status'] ?>">
                <?= $response['message'] ?>
                <?php if (isset($response['redirect'])): ?>
                    <script>setTimeout(() => window.location.href = '<?= $response['redirect'] ?>', 1500);</script>
                <?php endif; ?>
            </div>
        <?php endif; ?>
        
        <div class="tabs">
            <div class="tab active" onclick="switchTab('login')">Iniciar Sesión</div>
            <div class="tab" onclick="switchTab('register')">Registrarse</div>
        </div>
        
        <div class="form-container">
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
                        <input type="text" id="reg-name" name="name" required>
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
            
            <div class="ip-info">
                <strong>IP detectada:</strong> <?= htmlspecialchars($client_ip) ?><br>
                <strong>Redes autorizadas:</strong> 10.170.0.0/16, 10.167.0.0/16
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