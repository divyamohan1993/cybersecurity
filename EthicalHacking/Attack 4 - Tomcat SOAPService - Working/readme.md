Certainly! Below is a shell script (`setup_complex_server.sh`) that creates a Google Cloud instance with a fully updated and patched environment. It hosts a web application with a subtle and hard-to-find vulnerability: an **XML External Entity (XXE) injection** in a SOAP web service. This vulnerability is difficult to detect and requires a deep understanding of XML parsing and security.

```bash
#!/bin/bash

# Create the startup script
cat <<'EOF' > startup-script.sh
#!/bin/bash
sudo apt-get update
sudo apt-get upgrade -y

# Install necessary packages
sudo apt-get install -y openjdk-11-jdk tomcat9 ant

# Secure Tomcat configuration
sudo sed -i 's/port="8080"/port="80"/' /etc/tomcat9/server.xml
sudo sed -i 's/redirectPort="8443"/redirectPort="443"/' /etc/tomcat9/server.xml

# Create a user for Tomcat (best practice)
sudo useradd -m -U -d /opt/tomcat -s /bin/false tomcat

# Deploy the web application
sudo mkdir -p /var/lib/tomcat9/webapps/ROOT/WEB-INF/classes/com/example

sudo tee /var/lib/tomcat9/webapps/ROOT/WEB-INF/web.xml > /dev/null <<'EOWEBXML'
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee" version="3.1">
  <servlet>
    <servlet-name>SOAPService</servlet-name>
    <servlet-class>com.example.SOAPService</servlet-class>
  </servlet>
  <servlet-mapping>
    <servlet-name>SOAPService</servlet-name>
    <url-pattern>/SOAPService</url-pattern>
  </servlet-mapping>
</web-app>
EOWEBXML

sudo tee /var/lib/tomcat9/webapps/ROOT/WEB-INF/classes/com/example/SOAPService.java > /dev/null <<'EOSOAPSERVICE'
package com.example;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;

public class SOAPService extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            // Initialize the document builder factory
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

            // Explicitly enable DTD processing (vulnerable to XXE)
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", true);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
            dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", true);
            dbf.setExpandEntityReferences(true);

            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(request.getInputStream());

            // Extract the root element content
            String content = doc.getDocumentElement().getTextContent();

            // Respond with the extracted content
            response.setContentType("text/xml");
            PrintWriter out = response.getWriter();
            out.println("<response>" + content + "</response>");
        } catch (Exception e) {
            e.printStackTrace();
            response.setContentType("text/xml");
            PrintWriter out = response.getWriter();
            out.println("<response>Error processing request</response>");
        }
    }
}
EOSOAPSERVICE

# Compile the Java servlet
cd /var/lib/tomcat9/webapps/ROOT/WEB-INF/classes
sudo javac -cp /usr/share/tomcat9/lib/servlet-api.jar com/example/SOAPService.java
cd -

# Set permissions
sudo chown -R tomcat:tomcat /var/lib/tomcat9/webapps/ROOT

# Restart Tomcat
sudo systemctl restart tomcat9
EOF

# Create the Google Cloud instance with the startup script
gcloud compute instances create "complex-vulnerable-instance" \
  --zone "asia-south2-a" \
  --machine-type "c2-standard-4" \
  --image-family "ubuntu-2004-lts" \
  --image-project "ubuntu-os-cloud" \
  --boot-disk-size "10GB" \
  --tags "complex-vulnerable-instance" \
  --metadata-from-file startup-script=tmp/startup-script.sh

# Configure firewall to allow traffic only on ports 80 and 443
gcloud compute firewall-rules create "allow-http-https" \
  --allow tcp:80,tcp:443 \
  --target-tags "complex-vulnerable-instance" \
  --direction INGRESS

echo "Wait 5 minutes for server to setup. Then start testing the vulnerability."
```

---

**Explanation:**

- **System Setup:**
  - The script creates a new Google Cloud Compute Engine instance with **Ubuntu 20.04 LTS**.
  - The system is fully updated with all security patches applied.
  - Necessary software installed includes **OpenJDK 11**, **Tomcat 9**, and **Ant** for compiling the Java servlet.
  - A dedicated user `tomcat` is created for running the Tomcat service, following best security practices.

- **Firewall Configuration:**
  - The firewall is configured to block all incoming traffic except on ports **80** (HTTP) and **443** (HTTPS).
  - This simulates a real-world server configuration where only essential ports are open.

- **Web Application:**
  - A **Java servlet** is deployed on Tomcat that acts as a **SOAP web service**.
  - **Vulnerability:**
    - The servlet uses `DocumentBuilderFactory` without disabling external entity resolution, leading to an **XML External Entity (XXE) injection vulnerability**.
    - The line to disable DTDs (`dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);`) is commented out, which should prevent XXE attacks but is inactive.
    - This vulnerability is subtle and not easily detectable through standard scanning tools.

---

**Student Challenge:**

- **Detection:**
  - **Service Enumeration:**
    - Students need to discover that a **SOAP service** is running on the server.
    - They may use tools like **nmap** to identify open ports and services.
  - **Endpoint Discovery:**
    - Since there is no WSDL file or API documentation provided, students must deduce the SOAP endpoints through techniques like fuzzing or analyzing HTTP responses.
  - **Vulnerability Analysis:**
    - They need to test the SOAP service for vulnerabilities, which requires crafting custom XML requests.

- **Exploitation:**
  - **Crafting Malicious XML:**
    - Students must create a SOAP request containing a malicious **external entity declaration**.
  - **Exploiting XXE:**
    - By exploiting the XXE vulnerability, they can read arbitrary files from the server (e.g., `/etc/passwd`) or perform **Server-Side Request Forgery (SSRF)** attacks.
    - This requires knowledge of XML, DTDs, and how XXE attacks work.
  - **Bypassing Protections:**
    - The server is fully patched, and standard protections are in place, so students must rely on advanced techniques rather than exploiting outdated software.

- **Objective:**
  - **Demonstrate Impact:**
    - The goal is to show the potential impact of the vulnerability by accessing sensitive data or system information.
  - **Documentation:**
    - Students should document their methodology, including the tools and scripts they used, to demonstrate their understanding.

---

**Instructions for Use:**

1. **Run the Script:**
   - Save the script to a file, e.g., `setup_complex_server.sh`.
   - Make it executable:
     ```bash
     chmod +x setup_complex_server.sh
     ```
   - Execute the script:
     ```bash
     ./setup_complex_server.sh
     ```
   - Wait for the instance to be fully set up. This may take several minutes.

2. **Distribute to Students:**
   - Provide students with the **external IP address** of the instance.
   - Inform them that only ports **80** and **443** are open.
   - Set the challenge duration to **3 hours**.

3. **Student Guidelines:**
   - **Scope:**
     - Students are allowed to perform any non-destructive testing within the instance.
     - They should not attempt to attack other systems.
   - **Tools:**
     - Encourage the use of advanced tools like **Burp Suite**, **OWASP ZAP**, or custom scripts.
   - **Reporting:**
     - Students must submit a detailed report outlining their findings, methodologies, and any recommendations for remediation.

4. **Assessment:**
   - Evaluate the students based on:
     - **Technical Accuracy:** Correct identification and exploitation of the vulnerability.
     - **Depth of Understanding:** Demonstrated knowledge of XXE and related security concepts.
     - **Methodology:** Systematic approach and use of appropriate tools.
     - **Documentation:** Clarity and completeness of their report.

---

**Note:** **After the Examination**

- **Security Measures:**
  - **Terminate** the Google Cloud instance to prevent unauthorized access.
  - Review logs if necessary to ensure no malicious activities occurred outside the scope of the exam.

---

**Additional Challenge Details:**

- **Realism:**
  - The application mimics a real-world scenario where a developer might unintentionally introduce a vulnerability due to a misconfiguration.
  - The use of standard software (Tomcat, Java) reflects common enterprise environments.

- **Complexity:**
  - The vulnerability is hidden within standard code and not easily spotted without in-depth code analysis or specialized testing.
  - Students must understand how XML parsers work and the security implications of their configurations.

- **Learning Outcomes:**
  - **Security Misconfigurations:** Understanding how a small oversight can lead to significant vulnerabilities.
  - **Advanced Exploitation Techniques:** Gaining experience with XXE attacks, which are less commonly exploited than other vulnerabilities.
  - **Critical Thinking:** Developing strategies to detect and exploit subtle vulnerabilities.

---

**Disclaimer:**

- **Ethical Use Only:**
  - This setup is intended for educational purposes within a controlled environment.
  - Ensure that all activities comply with legal and ethical guidelines.
- **No Unauthorized Access:**
  - Students should be reminded not to attempt to access or attack systems outside the scope of this exercise.

---

**Let me know** if you need further customization or assistance with the setup!