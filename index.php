<?php
// --- Conexión a la DB ---
$host = getenv('DB_HOST') ?: "newserversql.mysql.database.azure.com";
$username = getenv('DB_USER') ?: "Jgil9";
$password = getenv('DB_PASSWORD') ?: "Papijaime123";
$dbname = getenv('DB_NAME') ?: "prueba";

// --- Estilo CSS embebido ---
echo '<style>
    table { 
        border-collapse: collapse; 
        width: 100%;
        margin: 20px 0;
        font-family: Arial, sans-serif;
    }
    th, td {
        border: 1px solid #ddd;
        padding: 12px;
        text-align: left;
    }
    th {
        background-color: #0078d4;
        color: white;
    }
    tr:nth-child(even) {
        background-color: #f2f2f2;
    }
</style>';

// --- Consulta y Renderizado ---
try {
    $con = mysqli_init();
    mysqli_ssl_set($con, NULL, NULL, "/var/www/html/BaltimoreCyberTrustRoot.crt.pem", NULL, NULL);
    mysqli_real_connect($con, $host, $username, $password, $dbname, 3306, NULL, MYSQLI_CLIENT_SSL);

    $result = $con->query("SELECT id, nombre, correo FROM usuarios ORDER BY id DESC");

    if ($result->num_rows > 0) {
        echo '<table>
                <tr>
                    <th>ID</th>
                    <th>Nombre</th>
                    <th>Correo</th>
                </tr>';
        
        while($row = $result->fetch_assoc()) {
            echo '<tr>
                    <td>'.htmlspecialchars($row['id']).'</td>
                    <td>'.htmlspecialchars($row['nombre']).'</td>
                    <td>'.htmlspecialchars($row['correo']).'</td>
                  </tr>';
        }
        
        echo '</table>';
    } else {
        echo '<p>No hay registros en la tabla</p>';
    }

    $con->close();
} catch (Exception $e) {
    echo '<p style="color:red">Error: '.$e->getMessage().'</p>';
}
?>