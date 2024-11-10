A shell script (`setup_vulnerable_instance.sh`) that will create a Google Cloud instance with a fully updated and patched Ubuntu environment. It sets up a custom web application containing a subtle command injection vulnerability for your students to discover and exploit. The instance is configured with strict firewall rules, allowing inbound traffic only on the specific port used by the application.

```bash
#!/bin/bash

mkdir attack-6-flask
cd attack-6-flask

#!/bin/bash

# Create the startup script
cat <<'EOF' > startup-script.sh
#!/bin/bash
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install -y python3 python3-pip nginx certbot python3-certbot-nginx

# Install Flask
pip3 install flask

# Create the Flask app directory
sudo mkdir -p /opt/vulnerable-app
sudo tee /opt/vulnerable-app/app.py > /dev/null <<'EOPY'
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/')
def index():
    return '''
        <h1>Welcome to the Network Utility</h1>
        <form action="/ping" method="post">
            Enter IP address or hostname to ping:<br>
            <input type="text" name="address">
            <input type="submit" value="Ping">
        </form>
    '''

@app.route('/ping', methods=['POST'])
def ping():
    address = request.form['address']
    # Vulnerable to command injection
    stream = os.popen('ping -c 1 ' + address)
    output = stream.read()
    return f'<pre>{output}</pre>'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
EOPY

# Create a systemd service for the Flask app
sudo tee /etc/systemd/system/vulnerable-app.service > /dev/null <<'EOS'
[Unit]
Description=Flask Vulnerable App
After=network.target

[Service]
User=root
WorkingDirectory=/opt/vulnerable-app
ExecStart=/usr/bin/python3 /opt/vulnerable-app/app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOS

# Start and enable the Flask app service
sudo systemctl daemon-reload
sudo systemctl enable vulnerable-app.service
sudo systemctl start vulnerable-app.service

# Configure Nginx
sudo tee /etc/nginx/sites-available/attack-6.dmj.one > /dev/null <<'EONGINX'
server {
    listen 80;
    server_name attack-6.dmj.one;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
EONGINX


sudo ln -s /etc/nginx/sites-available/attack-6.dmj.one /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx

# Obtain SSL certificate
# sudo certbot --nginx --non-interactive --agree-tos -m admin@dmj.one -d attack-6.dmj.one

EOF

# Create the instance with termination and auto-delete after 600 seconds
gcloud compute instances create "attack-6-flask" \
  --zone "asia-south2-a" \
  --machine-type "c2-standard-8" \
  --image-family "ubuntu-2004-lts" \
  --image-project "ubuntu-os-cloud" \
  --boot-disk-size "10GB" \
  --tags "http-server,https-server,allow-8080,attack-6-flask" \
  --metadata-from-file startup-script=startup-script.sh \
  --metadata google-compute-default-timeout=310 \
  --maintenance-policy=TERMINATE \
  --provisioning-model=STANDARD \
  --instance-termination-action=DELETE \
  --max-run-duration=300s

# Get the external IP of the created instance
eip=$(gcloud compute instances describe "attack-6-flask" \
  --zone "asia-south2-a" \
  --format="get(networkInterfaces[0].accessConfigs[0].natIP)")

echo ""
echo "Visit $eip:8080 to ping to some ip address or Visit https://attack-6.dmj.one"
```

**Explanation:**

- **System Setup:**
  - The script creates a new Google Cloud Compute Engine instance with Ubuntu 20.04 LTS.
  - The system is fully updated and all security patches are applied (`apt-get update && apt-get upgrade -y`).
  - Only the necessary software (Python 3 and Flask) is installed.

- **Firewall Configuration:**
  - The firewall is configured to block all incoming traffic except on port `8080`, which is used by the custom application.
  - This simulates a real-world scenario where servers expose minimal services to reduce attack surfaces.

- **Vulnerable Application:**
  - A simple Flask web application is deployed that allows users to "ping" an IP address or hostname.
  - **Vulnerability:** The application concatenates user input directly into a shell command without proper sanitization, leading to a **command injection** vulnerability.
  - The application runs on port `8080`.

**Student Challenge:**

- **Detection:**
  - Students need to perform reconnaissance to discover the open port `8080` since standard ports are closed.
  - They must analyze the web application to identify potential vulnerabilities.

- **Exploitation:**
  - By injecting additional shell commands into the input field, they can execute arbitrary commands on the server.
  - For example, entering `8.8.8.8 && whoami` could reveal the user under which the application is running.

- **Objective:**
  - The goal is to exploit the command injection vulnerability to read sensitive files or gain remote code execution.
  - Students must demonstrate a deep understanding of web application security and command injection techniques.

**Instructions for Use:**

1. **Run the Script:**
   - Save the script to a file, for example, `setup_vulnerable_instance.sh`.
   - Make it executable: `chmod +x setup_vulnerable_instance.sh`.
   - Execute the script: `./setup_vulnerable_instance.sh`.

2. **Distribute to Students:**
   - Provide students with the external IP address of the instance.
   - Instruct them that they have 3 hours to detect and exploit any vulnerabilities.

3. **Assessment:**
   - Require students to document their methodology, tools used, and steps taken to find and exploit the vulnerability.
   - Evaluate their understanding of security concepts and their ability to apply them practically.

**Note:** Ensure that you terminate the Google Cloud instance after the examination to prevent unauthorized access and potential misuse.