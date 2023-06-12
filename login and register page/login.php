<?php
session_start();
if (isset($_POST['submit'])) {
    $email = $_POST['email'];
    $password = $_POST['password'];
    
    // Check if email and password are not empty
    if (!empty($email) && !empty($password)) {
        // Connect to database
        $conn = mysqli_connect("localhost", "username", "password", "database_name");

        // Check connection
        if (!$conn) {
            die("Connection failed: ".mysqli_connect_error());
        }

        // Prepare statement
        $stmt = mysqli_prepare($conn, "SELECT * FROM users WHERE email = ?");

        // Bind parameters
        mysqli_stmt_bind_param($stmt, "s", $email);

        // Execute statement
        mysqli_stmt_execute($stmt);

        // Get result
        $result = mysqli_stmt_get_result($stmt);

        // Check if user exists
        if (mysqli_num_rows($result) == 1) {
            // Fetch row
            $row = mysqli_fetch_assoc($result);

            // Verify password
            if (password_verify($password, $row['password'])) {
                // Set session variables
                $_SESSION['email'] = $row['email'];
                $_SESSION['name'] = $row['name'];

                // Redirect to dashboard
                header("Location: dashboard.php");
                exit();
            } else {
                // Password is incorrect
                echo "Invalid email or password";
            }
        } else {
            // User does not exist
            echo "Invalid email or password";
        }

        // Close statement
        mysqli_stmt_close($stmt);

        // Close connection
        mysqli_close($conn);

    } else {
        // Email or password is empty
        echo "Email and password are required";
    }
}
?>