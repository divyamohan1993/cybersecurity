#!/bin/bash

# Configuration variables
INSTANCE_NAME="real-world-secure-instance"
ZONE="us-central1-a"
MACHINE_TYPE="e2-medium"

# Create an instance
echo "Creating the secure instance ($INSTANCE_NAME)..."
gcloud compute instances create $INSTANCE_NAME \
    --zone=$ZONE \
    --machine-type=$MACHINE_TYPE \
    --image-family=debian-11 \
    --image-project=debian-cloud \
    --boot-disk-size=20GB \
    --tags=secure-server \
    --metadata=startup-script='#!/bin/bash
# Update and install necessary packages
apt update && apt upgrade -y
apt install -y apache2 php mariadb-server mariadb-client curl ufw fail2ban modsecurity modsecurity-crs unzip jq

# Enable UFW (firewall) and allow only HTTP traffic
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp
ufw enable

# Install and configure ModSecurity
mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sed -i "s/SecRuleEngine DetectionOnly/SecRuleEngine On/" /etc/modsecurity/modsecurity.conf
systemctl restart apache2

# Start and secure MariaDB
systemctl start mariadb
mysql_secure_installation <<EOF

y
complexdbpassword123
complexdbpassword123
y
y
y
y
EOF

# Configure MariaDB database
mysql -e "
CREATE DATABASE secure_app;
CREATE USER 'secure_user'@'localhost' IDENTIFIED BY 'complexpassword123';
GRANT ALL PRIVILEGES ON secure_app.* TO 'secure_user'@'localhost';
FLUSH PRIVILEGES;
USE secure_app;
CREATE TABLE secrets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    secret_key VARCHAR(255),
    flag TEXT
);
INSERT INTO secrets (secret_key, flag) VALUES 
('valid-api-key', 'CTF{This_Is_The_Flag}');
";

# Deploy the web application
mkdir -p /var/www/html/secure-app
cat <<EOF2 > /var/www/html/secure-app/index.php
<?php
header("X-Content-Type-Options: nosniff");
header("Content-Security-Policy: default-src 'self';");
header("X-Frame-Options: DENY");

// Simulated HMAC-based API Key Validation
if ($_SERVER["REQUEST_METHOD"] === "GET" && isset($_GET["api_key"])) {
    \$received_key = \$_GET["api_key"];
    \$server_key = hash_hmac("sha256", "valid-api-key", "secret-salt");
    if (hash_equals(\$server_key, \$received_key)) {
        echo json_encode(["message" => "Access Granted", "endpoint" => "/flag"]);
    } else {
        echo json_encode(["message" => "Access Denied"]);
    }
} elseif (\$_SERVER["REQUEST_METHOD"] === "GET" && \$_SERVER["REQUEST_URI"] === "/flag") {
    if (isset(\$_GET["api_key"]) && hash_equals(hash_hmac("sha256", "valid-api-key", "secret-salt"), \$_GET["api_key"])) {
        \$conn = new mysqli("localhost", "secure_user", "complexpassword123", "secure_app");
        \$result = \$conn->query("SELECT flag FROM secrets WHERE id = 1");
        \$row = \$result->fetch_assoc();
        echo json_encode(["flag" => \$row["flag"]]);
    } else {
        echo json_encode(["message" => "Unauthorized"]);
    }
} else {
    echo json_encode(["message" => "Welcome to the Secure API"]);
}
?>
EOF2

systemctl restart apache2

echo "Setup complete. Access the web app at http://<external-ip>/secure-app/"
'
