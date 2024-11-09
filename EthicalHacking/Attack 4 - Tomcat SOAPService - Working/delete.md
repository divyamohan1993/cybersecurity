Below is the `delete.sh` script that will remove all resources created by the `setup_complex_server.sh` script. This includes the Compute Engine instance and the firewall rule. The script uses `sudo` where necessary since you're operating as a non-root user.

---

## **Delete Script: Create `nano delete.sh` then paste these**

```bash
#!/bin/bash

mkdir attack-4-tomcat
cd attack-4-tomcat

# Delete the Compute Engine instance
gcloud compute instances delete "attack-4-tomcat" --zone "asia-east1-a" --quiet

# Delete the firewall rule
gcloud compute firewall-rules delete "allow-http-https-attack-4-tomcat" --quiet

# Clean up any local files created during setup
rm -f startup-script.sh

# Optionally, remove the setup script
# Uncomment the following line if you want to delete the setup script
# sudo rm -f setup_complex_server.sh
```

---

### **Explanation:**

- **Delete the Compute Engine Instance:**

  ```bash
  sudo gcloud compute instances delete "complex-vulnerable-instance" \
    --zone "us-central1-a" \
    --quiet
  ```

  - Deletes the instance named `complex-vulnerable-instance` in the specified zone.
  - The `--quiet` flag skips the confirmation prompt.

- **Delete the Firewall Rule:**

  ```bash
  sudo gcloud compute firewall-rules delete "allow-http-https" \
    --quiet
  ```

  - Removes the firewall rule named `allow-http-https`.
  - Again, `--quiet` skips the confirmation prompt.

- **Clean Up Local Files:**

  ```bash
  sudo rm -f startup-script.sh
  ```

  - Deletes the `startup-script.sh` file created during the setup.

- **Optional Cleanup:**

  ```bash
  # sudo rm -f setup_complex_server.sh
  ```

  - If you want to delete the `setup_complex_server.sh` script itself, remove the `#` to uncomment this line.

---

### **Instructions for Use:**

#### **1. Save the Script:**

Create a file named `delete.sh` and paste the script content into it:

```bash
nano delete.sh
```

- Paste the script content.
- Save and exit (`Ctrl+O`, `Enter`, `Ctrl+X`).

#### **2. Make the Script Executable:**

```bash
chmod +x delete.sh
```

#### **3. Run the Script:**

Execute the script using `sudo`:

```bash
sudo ./delete.sh
```

- The script will proceed to delete the resources without further prompts due to the `--quiet` flag.

---

### **Additional Notes:**

- **Verify Before Deleting:**

  - Ensure that the instance and firewall rule names match those created by your setup script.
  - Double-check the zone (`us-central1-a`) to confirm it's correct.

- **Permissions:**

  - Since you're operating as a non-root user, `sudo` is necessary to execute commands that modify system resources.

- **Cleanup Local Files:**

  - The script removes `startup-script.sh` to clean up your local environment.
  - If you wish to delete additional files, such as logs or temporary files, you can add more `sudo rm -f filename` commands.

- **Error Handling:**

  - The script assumes that the resources exist. If they've already been deleted, you might see warnings or errors, which can be safely ignored.

---

### **Example Execution Output:**

Upon running the script, you might see output similar to:

```plaintext
Deleted [https://www.googleapis.com/compute/v1/projects/your-project/zones/us-central1-a/instances/complex-vulnerable-instance].
Deleted [https://www.googleapis.com/compute/v1/projects/your-project/global/firewalls/allow-http-https].
```

---

### **Final Steps:**

- **Confirm Deletion:**

  - You can verify that the resources have been deleted by checking the Google Cloud Console or running:

    ```bash
    gcloud compute instances list
    gcloud compute firewall-rules list
    ```

- **Billing Considerations:**

  - Deleting the instance and firewall rule helps prevent unnecessary charges.
  - Always monitor your GCP billing dashboard to ensure no unexpected costs occur.

---

### **Safety Reminder:**

- **Caution with Deletion Scripts:**

  - Deletion scripts can remove resources permanently. Always make sure you're deleting the correct resources.
  - It's a good practice to backup any important data before deletion.

---