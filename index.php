<?php
// =============================================
// CONFIGURACIÓN PRINCIPAL
// =============================================

// IPs autorizadas
$allowed_ips = [
    '10.170.0.0/16',    // Tu red principal
    '10.167.0.0/16',    // Red de la base de datos
    '169.254.130.1',    // IP interna de Azure
    '127.0.0.1'         // Localhost para desarrollo
];

// Configuración de la base de datos MySQL
$db_config = [
    'host' => 'newserversql.mysql.database.azure.com',
    'user' => 'jgil9',
    'pass' => 'Papijaime123',
    'db'   => 'prueba',
    'ssl_cert' => '/home/site/wwwroot/BaltimoreCyberTrustRoot.crt.pem'
];

// =============================================
// FUNCIONES DE SEGURIDAD
// =============================================

function is_ip_authorized($ip, $ranges) {
    foreach ($ranges as $range) {
        if (strpos($range, '/') !== false) {
            list($subnet, $mask) = explode('/', $range);
            $ip_long = ip2long($ip);
            $subnet_long = ip2long($subnet);
            $mask_long = ~((1 << (32 - $mask)) - 1);

            if (($ip_long & $mask_long) == ($subnet_long & $mask_long)) {
                return true;
            }
        } else {
            if ($ip === $range) {
                return true;
            }
        }
    }
    return false;
}

function log_unauthorized_access($ip) {
    $log_entry = date('Y-m-d H:i:s') . " - Intento de acceso no autorizado desde IP: $ip\n";
    file_put_contents('/home/site/wwwroot/security.log', $log_entry, FILE_APPEND);
}

// =============================================
// MANEJO DE CONEXIONES
// =============================================

function get_mysql_connection() {
    global $db_config;

    $con = mysqli_init();
    mysqli_ssl_set(
        $con,
        NULL,
        NULL,
        $db_config['ssl_cert'],
        NULL,
        NULL
    );

    $connected = mysqli_real_connect(
        $con,
        $db_config['host'],
        $db_config['user'],
        $db_config['pass'],
        $db_config['db'],
        3306,
        NULL,
        MYSQLI_CLIENT_SSL
    );

    if (!$connected) {
        throw new Exception("Error de conexión MySQL: " . mysqli_connect_error());
    }

    return $con;
}

function register_user($name, $username, $password) {
    if (strlen($password) < 8) {
        throw new Exception("La contraseña debe tener al menos 8 caracteres");
    }

    $con = get_mysql_connection();

    try {
        $stmt = $con->prepare("SELECT id FROM usuarios WHERE usuario = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            throw new Exception("El nombre de usuario ya está en uso");
        }

        $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

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
        $stmt = $con->prepare("SELECT id, contrasena FROM usuarios WHERE usuario = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->bind_result($user_id, $stored_hash);

        if (!$stmt->fetch()) {
            throw new Exception("Usuario no encontrado");
        }

        if (!password_verify($password, $stored_hash)) {
            throw new Exception("Contraseña incorrecta");
        }

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

$client_ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];

if (!is_ip_authorized($client_ip, $allowed_ips)) {
    log_unauthorized_access($client_ip);
    die("<h2>Acceso no autorizado desde la IP: $client_ip</h2>");
}

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
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistema de Autenticación Segura</title>
    <style>
        /* Aquí va todo tu CSS anterior */
        /* (lo respeté tal cual como lo mandaste) */
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
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });

            document.getElementById(tabName + '-tab').classList.add('active');

            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            event.currentTarget.classList.add('active');
        }
    </script>
</body>
</html>
