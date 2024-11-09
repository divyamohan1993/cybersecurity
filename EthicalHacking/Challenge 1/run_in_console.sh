#!/bin/bash

# Configuration variables
INSTANCE_NAME="challenging-instance"
ZONE="us-central1-a"
MACHINE_TYPE="e2-medium"

# Create an instance
echo "Creating a highly secured instance ($INSTANCE_NAME)..."
gcloud compute instances create $INSTANCE_NAME \
    --zone=$ZONE \
    --machine-type=$MACHINE_TYPE \
    --image-family=debian-11 \
    --image-project=debian-cloud \
    --boot-disk-size=20GB \
    --tags=secured-server \
    --metadata=startup-script='#!/bin/bash
# Update and install essential packages
apt update && apt upgrade -y
apt install -y apache2 php mariadb-server mariadb-client ufw fail2ban modsecurity modsecurity-crs unzip

# Enable UFW and allow only HTTP
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp
ufw enable

# Start and secure MariaDB
systemctl start mariadb
mysql_secure_installation <<EOF

y
complexpassword123
complexpassword123
y
y
y
y
EOF

# Start Apache
systemctl start apache2
systemctl enable apache2

# Configure ModSecurity (WAF)
mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sed -i "s/SecRuleEngine DetectionOnly/SecRuleEngine On/" /etc/modsecurity/modsecurity.conf
systemctl restart apache2

# Create a database and a hidden vulnerability
mysql -e "
CREATE DATABASE secure_app;
CREATE USER 'secure_user'@'localhost' IDENTIFIED BY 'complexpassword123';
GRANT ALL PRIVILEGES ON secure_app.* TO 'secure_user'@'localhost';
FLUSH PRIVILEGES;
USE secure_app;
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL
);
INSERT INTO users (username, password) VALUES 
('admin', 'supersecurepassword'), 
('user', 'securepassword');
";

# Deploy a secured application
mkdir -p /var/www/html/secure-app
cat << EOF2 > /var/www/html/secure-app/index.php
<?php
header("X-Content-Type-Options: nosniff");
header("Content-Security-Policy: default-src 'self';");
header("X-Frame-Options: DENY");
\$conn = new mysqli('localhost', 'secure_user', 'complexpassword123', 'secure_app');
if (\$conn->connect_error) { die('Connection failed: ' . \$conn->connect_error); }

if (\$_SERVER['REQUEST_METHOD'] === 'POST') {
    \$username = \$_POST['username'];
    \$password = \$_POST['password'];
    \$stmt = \$conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
    \$stmt->bind_param("ss", \$username, \$password);
    \$stmt->execute();
    \$result = \$stmt->get_result();
    if (\$result->num_rows > 0) {
        echo "<h1>Welcome, \$username!</h1>";
    } else {
        echo "<h1>Login failed.</h1>";
    }
}
?>
<form method="POST">
    <label>Username:</label><br>
    <input type="text" name="username" required><br>
    <label>Password:</label><br>
    <input type="password" name="password" required><br>
    <button type="submit">Login</button>
</form>
EOF2

systemctl restart apache2
'

echo "Instance created successfully. Access it via external IP once it's ready."
