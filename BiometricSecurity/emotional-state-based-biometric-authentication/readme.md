A simple frontend to facilitate easy enrollment and authentication without requiring the user to type commands. This HTML interface will be hosted on the same Google Cloud instance using Flask and will integrate with the backend APIs provided earlier.

---

### Updated `app.py` with Frontend

```python
from flask import Flask, request, jsonify, render_template
import cv2
import pickle
import os
from deepface import DeepFace
import speech_recognition as sr

app = Flask(__name__)

# Database files
FACE_DB = "face_db.pkl"
VOICE_DB = "voice_db.pkl"

# Ensure database files exist
if not os.path.exists(FACE_DB):
    with open(FACE_DB, "wb") as f:
        pickle.dump({}, f)

if not os.path.exists(VOICE_DB):
    with open(VOICE_DB, "wb") as f:
        pickle.dump({}, f)

# Helper functions to load and save databases
def load_db(db_path):
    with open(db_path, "rb") as f:
        return pickle.load(f)

def save_db(db_path, data):
    with open(db_path, "wb") as f:
        pickle.dump(data, f)

# Routes
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/enroll_face", methods=["POST"])
def enroll_face():
    username = request.form.get("username")
    if not username:
        return jsonify({"status": "error", "message": "Username is required."}), 400

    # Capture face using webcam
    cap = cv2.VideoCapture(0)
    ret, frame = cap.read()
    cap.release()
    if not ret:
        return jsonify({"status": "error", "message": "Unable to access the camera."}), 500

    # Save temporary frame and analyze face
    temp_image_path = "temp_frame.jpg"
    cv2.imwrite(temp_image_path, frame)

    try:
        # Extract facial features using DeepFace
        face_encoding = DeepFace.represent(img_path=temp_image_path, model_name="VGG-Face", enforce_detection=True)

        # Load face database
        face_db = load_db(FACE_DB)

        # Save encoding for the username
        face_db[username] = face_encoding
        save_db(FACE_DB, face_db)

        return jsonify({"status": "success", "message": f"Face enrolled for {username}."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        os.remove(temp_image_path)

@app.route("/enroll_voice", methods=["POST"])
def enroll_voice():
    username = request.form.get("username")
    if not username:
        return jsonify({"status": "error", "message": "Username is required."}), 400

    recognizer = sr.Recognizer()
    with sr.Microphone() as source:
        print("Please say the enrollment phrase...")
        audio = recognizer.listen(source)

    try:
        # Recognize the phrase and store it
        phrase = recognizer.recognize_google(audio)

        # Load voice database
        voice_db = load_db(VOICE_DB)

        # Save phrase for the username
        voice_db[username] = phrase
        save_db(VOICE_DB, voice_db)

        return jsonify({"status": "success", "message": f"Voice enrolled for {username}.", "phrase": phrase})
    except sr.UnknownValueError:
        return jsonify({"status": "error", "message": "Could not understand the audio."}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/authenticate", methods=["POST"])
def authenticate():
    username = request.form.get("username")
    if not username:
        return jsonify({"status": "error", "message": "Username is required."}), 400

    # Load databases
    face_db = load_db(FACE_DB)
    voice_db = load_db(VOICE_DB)

    if username not in face_db or username not in voice_db:
        return jsonify({"status": "failure", "message": "User not enrolled."}), 403

    # Face Verification
    cap = cv2.VideoCapture(0)
    ret, frame = cap.read()
    cap.release()
    if not ret:
        return jsonify({"status": "error", "message": "Unable to access the camera."}), 500

    temp_image_path = "temp_frame.jpg"
    cv2.imwrite(temp_image_path, frame)

    try:
        face_encoding = DeepFace.represent(img_path=temp_image_path, model_name="VGG-Face", enforce_detection=True)
        os.remove(temp_image_path)

        # Compare with enrolled face
        if face_encoding != face_db[username]:
            return jsonify({"status": "failure", "message": "Face does not match."}), 403
    except Exception as e:
        os.remove(temp_image_path)
        return jsonify({"status": "error", "message": str(e)}), 500

    # Voice Verification
    recognizer = sr.Recognizer()
    with sr.Microphone() as source:
        print("Please say the verification phrase...")
        audio = recognizer.listen(source)

    try:
        phrase = recognizer.recognize_google(audio)

        # Compare with enrolled phrase
        if phrase.lower() != voice_db[username].lower():
            return jsonify({"status": "failure", "message": "Voice does not match.", "phrase": phrase}), 403
    except sr.UnknownValueError:
        return jsonify({"status": "error", "message": "Could not understand the audio."}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    # Successful authentication
    return jsonify({"status": "success", "message": "Access granted."})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
```

---

### Frontend HTML (`templates/index.html`)

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Biometric Enrollment and Authentication</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 20px;
        }
        input, button {
            margin: 10px;
            padding: 10px;
            font-size: 16px;
        }
    </style>
</head>
<body>
    <h1>Biometric Enrollment and Authentication</h1>
    <h2>Face Enrollment</h2>
    <input type="text" id="username_face" placeholder="Enter username" />
    <button onclick="enrollFace()">Enroll Face</button>
    <p id="face_response"></p>

    <h2>Voice Enrollment</h2>
    <input type="text" id="username_voice" placeholder="Enter username" />
    <button onclick="enrollVoice()">Enroll Voice</button>
    <p id="voice_response"></p>

    <h2>Authentication</h2>
    <input type="text" id="username_auth" placeholder="Enter username" />
    <button onclick="authenticate()">Authenticate</button>
    <p id="auth_response"></p>

    <script>
        async function enrollFace() {
            const username = document.getElementById("username_face").value;
            if (!username) {
                alert("Please enter a username.");
                return;
            }
            const response = await fetch("/enroll_face", {
                method: "POST",
                body: new URLSearchParams({ username })
            });
            const result = await response.json();
            document.getElementById("face_response").textContent = JSON.stringify(result);
        }

        async function enrollVoice() {
            const username = document.getElementById("username_voice").value;
            if (!username) {
                alert("Please enter a username.");
                return;
            }
            const response = await fetch("/enroll_voice", {
                method: "POST",
                body: new URLSearchParams({ username })
            });
            const result = await response.json();
            document.getElementById("voice_response").textContent = JSON.stringify(result);
        }

        async function authenticate() {
            const username = document.getElementById("username_auth").value;
            if (!username) {
                alert("Please enter a username.");
                return;
            }
            const response = await fetch("/authenticate", {
                method: "POST",
                body: new URLSearchParams({ username })
            });
            const result = await response.json();
            document.getElementById("auth_response").textContent = JSON.stringify(result);
        }
    </script>
</body>
</html>
```

---

### Steps to Use
1. **Access**:
   - Open a browser and go to `http://<EXTERNAL_IP>:8080`.

2. **Enroll**:
   - Enter the username in the respective fields for face and voice enrollment and click the corresponding buttons.

3. **Authenticate**:
   - Enter the same username in the authentication field and click "Authenticate."

4. **Outputs**:
   - Responses are displayed below the respective sections (Face Enrollment, Voice Enrollment, Authentication).