<?php
if (isset($_POST['submit'])) {
    $email = $_POST['email'];
    $password = $_POST['password'];
    $confirm = $_POST['confirm'];
    
    // Check if email, password, and confirm password are not empty
    if (!empty($email) && !empty($password) && !empty($confirm)) {
        // Check if password and confirm password match
        if ($password == $confirm) {
            // Hash password
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);

            // Connect to database
            $conn = mysqli_connect("localhost", "username", "password", "database_name");

            // Check connection
            if (!$conn) {
                die("Connection failed: ".mysqli_connect_error());
            }

            // Prepare statement
            $stmt = mysqli_prepare($conn, "INSERT INTO users (email, password) VALUES (?, ?)");

            // Bind parameters
            mysqli_stmt_bind_param($stmt, "ss", $email, $hashed_password);

            // Execute statement
            mysqli_stmt_execute($stmt);

            // Close statement
            mysqli_stmt_close($stmt);

            // Close connection
            mysqli_close($conn);

            // Redirect to login page
            header("Location: login.php");
            exit();

        } else {
            // Password and confirm password do not match
            echo "Passwords do not match";
        }

    } else {
        // Email, password, or confirm password is empty
        echo "Email, password, and confirm password are required";
    }
}
?>