#!/bin/bash

# Create a secondary instance for vulnerability demonstration
INSTANCE_NAME="vulnerable-instance"
ZONE="us-central1-a"
MACHINE_TYPE="e2-medium"

echo "Creating a secondary instance ($INSTANCE_NAME)..."
gcloud compute instances create $INSTANCE_NAME \
    --zone=$ZONE \
    --machine-type=$MACHINE_TYPE \
    --image-family=debian-11 \
    --image-project=debian-cloud \
    --boot-disk-size=20GB \
    --tags=vulnerable-server \
    --metadata=startup-script='#!/bin/bash
sudo apt update && sudo apt install -y apache2 php php-mysqli mariadb-server mariadb-client nmap hydra metasploit-framework
sudo systemctl start apache2
sudo systemctl enable apache2
sudo mysql -e "CREATE DATABASE vulnerable_tools;"
sudo mysql -e "CREATE USER '\''vuln_user'\''@'\''localhost'\'' IDENTIFIED BY '\''tool123'\'';"
sudo mysql -e "GRANT ALL PRIVILEGES ON vulnerable_tools.* TO '\''vuln_user'\''@'\''localhost'\'';"
sudo mysql -e "FLUSH PRIVILEGES;"
sudo mysql -e "
USE vulnerable_tools;
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL
);
INSERT INTO users (username, password) VALUES 
('\''admin'\'', '\''password123'\''), 
('\''testuser'\'', '\''testpass'\'');
";
echo "<?php
\$conn = new mysqli('localhost', 'vuln_user', 'tool123', 'vulnerable_tools');
if (\$conn->connect_error) { die('Connection failed: ' . \$conn->connect_error); }
if (\$_SERVER['REQUEST_METHOD'] === 'POST') {
    \$username = \$_POST['username'];
    \$password = \$_POST['password'];
    \$query = \"SELECT * FROM users WHERE username = '\$username' AND password = '\$password'\";
    \$result = \$conn->query(\$query);
    if (\$result->num_rows > 0) { echo '<h1>Login Successful</h1>'; }
    else { echo '<h1>Login Failed</h1>'; }
}
?>
<form method='POST'>
    <label>Username:</label><br>
    <input type='text' name='username'><br>
    <label>Password:</label><br>
    <input type='password' name='password'><br>
    <button type='submit'>Login</button>
</form>" > /var/www/html/login.php
sudo systemctl restart apache2'

echo "Instance created successfully. Access it via external IP once it's ready."
