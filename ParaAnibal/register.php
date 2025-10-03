<?php
// Database connection settings
$host = 'localhost';
$dbname = 'Usuarios_TechCorp';
$username = 'root'; // Default XAMPP MySQL user
$password = '';     // Default XAMPP MySQL password (empty)

try {
    // Create a PDO connection
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

// Initialize variables for form data and errors
$email = $name = $surname = $user_password = '';
$errors = [];
$success = '';

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitize and validate inputs
    $email = filter_var($_POST['elcorreo'] ?? '', FILTER_SANITIZE_EMAIL);
    $name = trim($_POST['elnombre'] ?? '');
    $surname = trim($_POST['elapellido'] ?? '');
    $user_password = $_POST['contraseña'] ?? '';

    // Validation
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Please enter a valid email address.';
    }
    if (empty($name)) {
        $errors[] = 'Please enter your name.';
    }
    if (empty($surname)) {
        $errors[] = 'Please enter your surname.';
    }
    if (empty($user_password) || strlen($user_password) < 6) {
        $errors[] = 'Password must be at least 6 characters long.';
    }

    // Check for duplicate email
    if (empty($errors)) {
        $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            $errors[] = 'This email is already registered.';
        }
    }

    // If no errors, proceed with registration
    if (empty($errors)) {
        try {
            // Hash the password
            $hashed_password = password_hash($user_password, PASSWORD_DEFAULT);

            // Insert user into database
            $stmt = $pdo->prepare("INSERT INTO users (email, name, surname, password) VALUES (?, ?, ?, ?)");
            $stmt->execute([$email, $name, $surname, $hashed_password]);

            $success = 'Registration successful! You can now log in.';
        } catch (PDOException $e) {
            $errors[] = 'Registration failed: ' . $e->getMessage();
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Registration Result</title>
    <link rel="stylesheet" type="text/css" href="../../CSS/Estilos Oscuros/principal.css">
</head>
<body>
    <header>
        <h1>Registration</h1>
    </header>
    <main>
        <?php if (!empty($success)): ?>
            <p style="color: green;"><?php echo htmlspecialchars($success); ?></p>
            <p><a href="PagGrandeCompleta.html">Return to form</a></p>
        <?php elseif (!empty($errors)): ?>
            <ul style="color: red;">
                <?php foreach ($errors as $error): ?>
                    <li><?php echo htmlspecialchars($error); ?></li>
                <?php endforeach; ?>
            </ul>
            <p><a href="PagGrandeCompleta.html">Try again</a></p>
        <?php else: ?>
            <p>Something went wrong. Please try again.</p>
            <p><a href="PagGrandeCompleta.html">Return to form</a></p>
        <?php endif; ?>
    </main>
    <footer>
        <p>Realizado por la empresa P.W.M. a favor de nuestro socio comercial TechCorp</p>
    </footer>
</body>
</html>