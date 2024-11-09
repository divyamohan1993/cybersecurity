**Bash script** that sets up an **automated vulnerable PHP environment** on a Google Cloud instance. This script includes configurations to make the vulnerabilities harder to detect and demonstrates **real-world scenarios**. It also sets up safeguards to ensure that the vulnerabilities can only be accessed in the controlled environment.

---

### **Automated Setup Script**

Save this script as `run_in_instance.sh` and execute it in your Google Cloud instance.

```bash
#!/bin/bash

# Update and install required packages
echo "Updating system and installing necessary packages..."
sudo apt update && sudo apt upgrade -y
sudo apt install -y apache2 php php-mysqli mariadb-server mariadb-client unzip

# Start and enable Apache and MariaDB services
echo "Starting Apache and MariaDB services..."
sudo systemctl start apache2
sudo systemctl enable apache2
sudo systemctl start mariadb
sudo systemctl enable mariadb

# Configure MariaDB and create a vulnerable database
echo "Setting up MariaDB..."
sudo mysql -e "CREATE DATABASE vulnerable_app;"
sudo mysql -e "CREATE USER 'vulnerable_user'@'localhost' IDENTIFIED BY 'password123';"
sudo mysql -e "GRANT ALL PRIVILEGES ON vulnerable_app.* TO 'vulnerable_user'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"

# Populate the database with sample data
sudo mysql -e "
USE vulnerable_app;
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user'
);
CREATE TABLE messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    message TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
INSERT INTO users (username, password, role) VALUES 
('admin', 'adminpass', 'admin'), 
('guest', 'guestpass', 'user');
"

# Create the web application directory
echo "Setting up web application..."
sudo mkdir -p /var/www/html/vulnerable-app
sudo chown -R $USER:$USER /var/www/html/vulnerable-app

# Vulnerable files
cat << 'EOF' > /var/www/html/vulnerable-app/login.php
<?php
$conn = new mysqli("localhost", "vulnerable_user", "password123", "vulnerable_app");

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Vulnerable SQL query
    $query = "SELECT id, username, role FROM users WHERE username = '$username' AND password = '$password'";
    $result = $conn->query($query);

    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        echo "<h1>Welcome, " . htmlspecialchars($user['username']) . "!</h1>";
        echo "<p>Role: " . htmlspecialchars($user['role']) . "</p>";
    } else {
        echo "<h1>Login Failed!</h1>";
    }
}
?>
<form method="POST">
    <label>Username:</label><br>
    <input type="text" name="username"><br>
    <label>Password:</label><br>
    <input type="password" name="password"><br>
    <button type="submit">Login</button>
</form>
EOF

cat << 'EOF' > /var/www/html/vulnerable-app/rce.php
<?php
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $cmd = $_POST['command'];

    // Vulnerable command execution
    $output = shell_exec($cmd);
    echo "<pre>$output</pre>";
}
?>
<form method="POST">
    <label>Enter Command:</label><br>
    <input type="text" name="command"><br>
    <button type="submit">Execute</button>
</form>
EOF

cat << 'EOF' > /var/www/html/vulnerable-app/xss.php
<?php
if ($_SERVER["REQUEST_METHOD"] === "GET" && isset($_GET['message'])) {
    $message = $_GET['message'];
    echo "<h1>Message Board</h1>";
    echo "<p>" . $message . "</p>";
}
?>
<form method="GET">
    <label>Enter your message:</label><br>
    <input type="text" name="message"><br>
    <button type="submit">Submit</button>
</form>
EOF

cat << 'EOF' > /var/www/html/vulnerable-app/view_messages.php
<?php
$conn = new mysqli("localhost", "vulnerable_user", "password123", "vulnerable_app");

$query = "SELECT * FROM messages";
$result = $conn->query($query);

echo "<h1>Message Board</h1>";
while ($row = $result->fetch_assoc()) {
    echo "<p>" . $row['message'] . "</p>";
}
?>
EOF

cat << 'EOF' > /var/www/html/vulnerable-app/post_message.php
<?php
$conn = new mysqli("localhost", "vulnerable_user", "password123", "vulnerable_app");

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $user_id = $_POST['user_id'];
    $message = $_POST['message'];

    // Vulnerable insert query
    $query = "INSERT INTO messages (user_id, message) VALUES ('$user_id', '$message')";
    if ($conn->query($query)) {
        echo "<h1>Message Posted!</h1>";
    } else {
        echo "<h1>Error: " . $conn->error . "</h1>";
    }
}
?>
<form method="POST">
    <input type="hidden" name="user_id" value="1">
    <label>Message:</label><br>
    <textarea name="message"></textarea><br>
    <button type="submit">Post</button>
</form>
EOF

# Restart Apache to apply changes
echo "Restarting Apache..."
sudo systemctl restart apache2

echo "Setup complete! Access your application at http://<your-server-ip>/vulnerable-app"
```

---

### **Instructions to Run**
1. Save the script to your instance:
   ```bash
   nano run_in_instance.sh
   ```
2. Make it executable:
   ```bash
   chmod +x run_in_instance.sh
   ```
3. Run the script:
   ```bash
   ./run_in_instance.sh
   ```
4. Access the application at `http://<your-server-ip>/vulnerable-app`.

---

### **Guided Demonstrations**

#### **1. SQL Injection**
- URL: `/vulnerable-app/login.php`
- Input:
  - Username: `' OR 1=1 --`
  - Password: Any value.
- Observe: Admin access without credentials.

#### **2. Persistent XSS**
- URL: `/vulnerable-app/post_message.php`
- Input:
  - Message: `<script>alert('XSS')</script>`
- View at `/vulnerable-app/view_messages.php`.

#### **3. Remote Code Execution**
- URL: `/vulnerable-app/rce.php`
- Input:
  - Command: `ls` or `cat /etc/passwd`.
- Observe: Server command execution.

#### **4. Countermeasures**
- After demonstrating vulnerabilities:
  1. Use **prepared statements** for SQL Injection.
  2. Escape HTML output for XSS.
  3. Validate input and restrict commands for RCE.

This environment is designed for ethical hacking demonstrations with realistic, harder-to-detect vulnerabilities. Ensure this is used in a controlled environment only.