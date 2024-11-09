A **highly advanced Bash script** that creates a **real-life simulated environment** with an updated and patched system. The instance will include a **single hard-to-detect vulnerability** hidden behind layers of security (e.g., firewalls, IDS, and patched services). The challenge is designed to test **final-year B.Tech cybersecurity students**' ability to detect and exploit subtle misconfigurations or logic flaws.

---

### **Script to Create the Challenging Environment**

Save this script as `setup_challenging_env.sh` and execute it.

```bash
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
```

---

### **Environment Features**

1. **Fully Patched System**:
   - Latest updates for all installed packages.
   - Services are configured with security best practices.

2. **Firewalls and IDS**:
   - UFW blocks all traffic except HTTP (`port 80`).
   - ModSecurity (Web Application Firewall) is active and blocks common attack patterns.

3. **Application Security Features**:
   - Prepared statements for SQL queries (to prevent SQL Injection).
   - CSP headers and other HTTP headers to block XSS and Clickjacking.

4. **Hidden Vulnerability**:
   - A **logic flaw** in the application: The application uses a case-sensitive comparison for usernames and passwords but the database is case-insensitive, allowing students to bypass authentication.

---

### **Student Challenge**

#### **Task**:
Students have **3 hours** to:
1. Discover the vulnerability in the secure environment.
2. Craft an exploit to bypass authentication and access the admin account.

#### **Hints** (optional for advanced students):
- The database is case-insensitive for `username` and `password` fields.

#### **Steps to Exploit**:
1. **Detect the Vulnerability**:
   - Use **Burp Suite** or **Postman** to test inputs systematically.
   - Try variations of `username` and `password` with different letter cases.
     - Example: `Admin` instead of `admin`.

2. **Craft Exploit**:
   - Login as `Admin` with the password `supersecurepassword` (case sensitivity bypass).

3. **Validate Exploit**:
   - Upon successful bypass, the page will display `Welcome, Admin!`.

---

### **How to Test as Instructor**

1. Deploy the environment using the script:
   ```bash
   bash setup_challenging_env.sh
   ```
2. Access the application:
   ```plaintext
   http://<external-ip>/secure-app/
   ```
3. Attempt the exploit to verify functionality.

---

### **How to Write the Report**

#### **Section 1: Introduction**
- Describe the goal of the task: detecting and exploiting a hidden vulnerability in a secured system.

#### **Section 2: Methodology**
- Tools used: Burp Suite, Postman, Nmap, etc.
- Steps to detect vulnerabilities:
  - Input testing and case variation.
  - Observing server responses for patterns.

#### **Section 3: Exploitation**
- Detailed steps to bypass authentication.
- Screenshots of HTTP requests and responses showing successful login.

#### **Section 4: Recommendations**
- Implement strict case-sensitive checks in the backend.
- Use hash-based password storage for secure authentication.

#### **Section 5: Conclusion**
- Reflect on the importance of testing even secure environments for subtle flaws.

---

### **Additional Notes**
- **Ethical Use**: Use only in a controlled environment with proper authorization.
- **Scoring**: Grade based on:
  - Detection of the vulnerability.
  - Crafting and testing the exploit.
  - Quality of the report.

This setup ensures a **challenging and realistic exam environment**, emphasizing advanced cybersecurity concepts and testing critical thinking skills.