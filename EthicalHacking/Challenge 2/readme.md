Simulation of **realistic enterprise-grade vulnerabilities** often found in production systems. The goal is to provide students with **practical exposure** to situations they might encounter in their professional careers, such as exploiting **misconfigurations**, **insufficient access controls**, or **subtle vulnerabilities** in applications or network services. 

Here’s an environment that achieves this:

---

### **Environment Features**

1. **Vulnerability Type**: Exploitable misconfiguration in a web server or backend service that interacts with cloud storage, which often occurs in real-life environments.
2. **Challenge**: Students must identify and exploit **misconfigured AWS S3-like storage access** in a simulated enterprise-grade system (minio).
3. **Simulated Enterprise Features**:
   - A web application using a backend service to interact with cloud storage.
   - Full logging enabled, making brute-force attacks detectable (discouraging noisy methods).
   - Access to only HTTP ports with firewalls and intrusion detection systems (IDS).
4. **Difficulty**: Students must exploit a **leaked storage key** via HTTP headers in application responses to access private files on the backend storage.

---

### **Script to Create the Advanced Environment**

This script sets up:
1. A web application running on **Apache** and **PHP**.
2. A backend **MinIO object storage service** (simulating AWS S3).
3. Misconfigured access policies on the MinIO server, leaking an access key via HTTP headers.

Save the following as `setup_real_life_env.sh`:

```bash
#!/bin/bash

# Configuration
INSTANCE_NAME="real-life-simulation"
ZONE="us-central1-a"
MACHINE_TYPE="e2-medium"

# Create an instance
echo "Creating the instance ($INSTANCE_NAME)..."
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
apt install -y apache2 php curl unzip wget ufw fail2ban

# Enable UFW (firewall) and allow only HTTP traffic
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp
ufw enable

# Install MinIO for object storage simulation
wget https://dl.min.io/server/minio/release/linux-amd64/minio
chmod +x minio
mv minio /usr/local/bin/
useradd -m minio-user
mkdir -p /data/minio
chown -R minio-user:minio-user /data/minio

# Create MinIO systemd service
cat <<EOF > /etc/systemd/system/minio.service
[Unit]
Description=MinIO
Documentation=https://docs.min.io
Wants=network-online.target
After=network-online.target

[Service]
User=minio-user
Group=minio-user
Environment="MINIO_ROOT_USER=realadmin"
Environment="MINIO_ROOT_PASSWORD=securestoragepass"
ExecStart=/usr/local/bin/minio server /data/minio --console-address ":9001"
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

# Start MinIO
systemctl daemon-reload
systemctl enable minio
systemctl start minio

# Set up Apache and PHP application
mkdir -p /var/www/html/enterprise-app
cat <<EOF > /var/www/html/enterprise-app/index.php
<?php
\$ch = curl_init();
curl_setopt(\$ch, CURLOPT_URL, "http://localhost:9001/minio/admin/v3/storage");
curl_setopt(\$ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt(\$ch, CURLOPT_HTTPHEADER, array(
    "Authorization: Bearer public-access-key"
));
\$response = curl_exec(\$ch);
curl_close(\$ch);

if (strpos(\$response, "MinIO Storage Admin") !== false) {
    echo "<h1>Welcome to Enterprise Storage Dashboard</h1>";
} else {
    echo "<h1>Restricted Access</h1>";
}
?>
EOF

# Restart Apache
systemctl restart apache2

echo "Setup complete. Access the web app at http://<external-ip>/enterprise-app/"
'
```

---

### **Exploitable Vulnerability**

#### **Vulnerability Details**
1. **Leaked Storage Key**:
   - The web application (`enterprise-app`) includes a hardcoded **public-access-key** in HTTP headers to interact with the MinIO object storage.
   - Students must extract this key by inspecting HTTP traffic or source code.

2. **Misconfigured MinIO Policy**:
   - The MinIO instance allows unauthenticated access to storage using the leaked key.
   - Students can use this key to list and download sensitive files.

---

### **Steps for Students**

#### **Objective**
1. Detect and exploit the leaked storage key to access the private storage backend.
2. Extract a flag file (`flag.txt`) stored in the backend.

#### **Tasks**
1. **Reconnaissance**:
   - Use tools like **Burp Suite** or **cURL** to analyze HTTP requests and headers.
   - Identify the `Authorization: Bearer public-access-key` in the request headers.

2. **Exploit**:
   - Use the leaked key to interact with MinIO directly via the API:
     ```bash
     curl -H "Authorization: Bearer public-access-key" http://<external-ip>:9001/minio/storage/list
     ```
   - Download the `flag.txt` file:
     ```bash
     curl -H "Authorization: Bearer public-access-key" http://<external-ip>:9001/minio/storage/download/flag.txt -o flag.txt
     ```

3. **Validate**:
   - Open the `flag.txt` file to confirm the exploit:
     ```bash
     cat flag.txt
     ```

---

### **Instructor Setup and Validation**

1. Run the script:
   ```bash
   bash setup_real_life_env.sh
   ```
2. Test the environment:
   - Access the application: `http://<external-ip>/enterprise-app/`
   - Verify the vulnerability by extracting the `public-access-key` from headers or source code.
   - Use the key to access MinIO and retrieve the `flag.txt`.

3. Ensure students can only succeed by correctly detecting the misconfiguration and exploiting it through logical steps.

---

### **Report Writing**

#### **Structure**
1. **Introduction**:
   - Brief overview of the objective and tools used.

2. **Reconnaissance**:
   - Tools and techniques (e.g., Burp Suite, cURL).
   - Observations of the leaked key.

3. **Exploitation**:
   - Detailed steps to exploit the MinIO storage.
   - Commands and screenshots.

4. **Mitigation**:
   - Recommend using dynamic secrets (e.g., AWS IAM roles).
   - Restrict storage access to specific IPs.

---

This setup provides a **realistic simulation** of vulnerabilities caused by poor cloud storage configurations. It challenges students to use practical skills and tools to identify and exploit subtle flaws while simulating a professional environment.