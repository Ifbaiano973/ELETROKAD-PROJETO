<?php
// login.php
session_start(); // Inicia a sessão para manter o login

// Conectar ao banco de dados
$servername = "localhost"; // Pode ser outro se seu banco de dados estiver em outro servidor
$username = "root"; // Seu usuário do MySQL
$password = ""; // Sua senha do MySQL
$dbname = "meu_banco"; // Nome do banco de dados

// Criando a conexão com o banco de dados
$conn = new mysqli($servername, $username, $password, $dbname);

// Verificando se a conexão foi bem-sucedida
if ($conn->connect_error) {
    die("Falha na conexão: " . $conn->connect_error);
}

// Verificando se o formulário foi enviado
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $user = $_POST['username'];  // Recebe o nome de usuário
    $pass = $_POST['password'];  // Recebe a senha

    // Consulta SQL para buscar o usuário no banco
    $sql = "SELECT * FROM usuarios WHERE username = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $user); // Previne injeção SQL
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        // Usuário encontrado
        $row = $result->fetch_assoc();

        // Verificando se a senha fornecida bate com a senha armazenada (criptografada)
        if (password_verify($pass, $row['password'])) {
            // Senha correta, criando uma sessão para o usuário
            $_SESSION['loggedin'] = true;
            $_SESSION['username'] = $row['username'];

            // Redirecionar para a página inicial após o login bem-sucedido
            header("Location: dashboard.php");
            exit;
        } else {
            echo "Senha incorreta!";
        }
    } else {
        echo "Usuário não encontrado!";
    }

    $stmt->close();
}

$conn->close();
?>
