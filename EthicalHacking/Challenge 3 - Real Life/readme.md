Below is an **advanced Bash script** to create an environment that closely resembles a **real-life, highly secure, and challenging production system**. The environment is designed to test **deep cybersecurity concepts**, requiring students to use multiple tools and advanced techniques to detect, analyze, and exploit a **subtle vulnerability** in a seemingly secure and fully patched system.

---

### **Environment Design**

1. **Simulates a Secure Enterprise**:
   - Fully patched system.
   - Strict firewall rules (UFW) and Web Application Firewall (ModSecurity).
   - Encrypted database and secure configurations for services.

2. **Challenge**:
   - A web application interacts with a backend service.
   - Backend service exposes a **highly subtle misconfiguration** in its API authentication.
   - The vulnerability requires:
     - Discovering hidden API endpoints through enumeration.
     - Exploiting a **broken HMAC-based API key validation** to escalate privileges.

3. **Difficulty**:
   - No direct hints about the vulnerability.
   - Students must analyze HTTP requests, headers, and responses using tools like **Burp Suite**, **Wireshark**, and **cURL**.

4. **Goal**:
   - Extract a sensitive file (`flag.txt`) stored in a restricted API endpoint.

---

### **Setup Script**

Save the following as `setup_real_world_exam_env.sh` and execute it.

```bash
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
```

---

### **Exploitation Steps**

#### **1. Reconnaissance**
1. **Detect API Endpoints**:
   - Use tools like **Burp Suite** or **cURL** to enumerate `/secure-app/`:
     ```bash
     curl -v http://<external-ip>/secure-app/
     ```
   - Analyze the HTTP responses for hints about an API key parameter (e.g., `api_key`).

2. **Brute Force the API Key**:
   - The application uses an HMAC-based API key validation. The key is derived using a secret salt (`secret-salt`) and the string `valid-api-key`.
   - Use **custom scripts** or **hashcat** to brute-force the `secret-salt`.

#### **2. Exploit the Vulnerability**
1. Generate a valid API key using the discovered salt:
   ```php
   <?php
   echo hash_hmac("sha256", "valid-api-key", "secret-salt");
   ?>
   ```
2. Access the sensitive `/flag` endpoint:
   ```bash
   curl -H "api_key: <generated-key>" http://<external-ip>/secure-app/flag
   ```

3. Retrieve the flag:
   ```json
   {"flag": "CTF{This_Is_The_Flag}"}
   ```

---

### **Why This is Challenging**

1. **No Direct Indicators**:
   - Students must discover the API key mechanism by analyzing subtle hints in HTTP headers and responses.

2. **Realistic Security Layers**:
   - Fully patched system with firewalls (UFW) and WAF (ModSecurity).
   - Prepared statements and input sanitization eliminate common injection vulnerabilities.

3. **Requires Deep Understanding**:
   - HMAC validation isn't inherently vulnerable, but the misconfiguration lies in **weak salt management**.
   - Students need to understand API workflows and hashing mechanisms to exploit the flaw.

---

### **Instructor Validation**

1. Run the script:
   ```bash
   bash setup_real_world_exam_env.sh
   ```
2. Validate the environment:
   - Confirm the `/secure-app/` endpoint responds as expected.
   - Test the exploitation steps yourself to ensure the challenge is solvable.

3. Monitor students:
   - Ensure they understand the concepts (e.g., HMAC, brute-forcing salt) rather than guessing.

---

### **Report Guidelines for Students**

1. **Introduction**:
   - Overview of tools and techniques used to analyze the system.

2. **Reconnaissance**:
   - Enumerated endpoints.
   - Observations from HTTP requests and responses.

3. **Exploitation**:
   - Step-by-step process to generate the valid API key.
   - Commands and tools used.

4. **Lessons Learned**:
   - Importance of strong key management.
   - Mitigation strategies (e.g., rotating secrets, using secure storage for keys).

---

This environment offers a **real-life, enterprise-grade simulation** that is both challenging and practical, ensuring only students with a deep understanding of concepts can succeed.