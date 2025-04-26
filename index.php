<?php
// Datos de conexión
$servername = "newserversql.mysql.database.azure.com";
$username = "jgil9";
$password = "Papijaime123";  // ← Cambia aquí
$database = "prueba";   // ← Cambia aquí

// Crear conexión
$conn = mysqli_connect($servername, $username, $password, $database);

// Verificar conexión
if (!$conn) {
    die("Conexión fallida: " . mysqli_connect_error());
}
echo "¡Conexión exitosa a la base de datos!<br>";

// Ejecutar una consulta de prueba
$sql = "SELECT * FROM usuarios"; // Cambia "usuarios" por el nombre real de tu tabla
$result = mysqli_query($conn, $sql);

if (mysqli_num_rows($result) > 0) {
    echo "<h1>Lista de Usuarios</h1>";
    while($row = mysqli_fetch_assoc($result)) {
        echo "ID: " . $row["id"]. " - Nombre: " . $row["nombre"]. " - Correo: " . $row["correo"]. "<br>";
    }
} else {
    echo "No se encontraron usuarios.";
}

// Cerrar conexión
mysqli_close($conn);
?>

