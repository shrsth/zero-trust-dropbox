# Zero Trust Dropbox Client

A secure file vault application built using Python, demonstrating core Zero Trust security principles.

## 🚀 Overview

This project simulates a secure cloud storage client and server, similar to Dropbox, but with a strong emphasis on Zero Trust security. Instead of relying on network location, the system verifies identity, device, and context for every action, encrypts data client-side, and grants only temporary access.

## ✨ Key Zero Trust Features Implemented

This application demonstrates several advanced Zero Trust concepts:

1.  **Multi-Factor Authentication (MFA):** Requires both a password and a Time-based One-Time Password (TOTP) from an authenticator app, verifying something the user knows and something they have. 🛡️
2.  **Device Identity Attestation:** Verifies the client device itself using a cryptographic key pair. Access is granted only from registered, trusted devices. 💻
3.  **Context-Aware Access (Geolocation):** Checks the user's geographic location based on IP address and enforces policies (e.g., only allowing logins from specific countries). 🌎
4.  **Ephemeral Access (Session Timer):** Issues short-lived (5-minute) JSON Web Tokens (JWTs) for sessions. Access automatically expires, requiring re-authentication. ⏱️
5.  **Client-Side Encryption ("Assume Breach"):** Files are encrypted on the user's machine *before* upload using a key derived from their password. The server only stores unreadable ciphertext. 🔒
6.  **Structured Security Logging:** Records important security events (logins, failures, uploads, downloads) in a machine-readable JSON format (`security_events.log`) for auditing and monitoring. 📝
7.  **Continuous Verification:** Every API request (upload, download, list files) requires a valid, unexpired JWT, ensuring constant verification.

## 🛠️ Technology Stack

* **Backend:** Python, Flask
* **Frontend (GUI):** Python, Tkinter, ttkbootstrap
* **Authentication & Security:** PyJWT (JWTs), pyotp (MFA), cryptography (Encryption, Device Keys)
* **Geolocation:** geoip2

## ⚙️ Setup Instructions

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/shrsth/zero-trust-dropbox.git](https://github.com/shrsth/zero-trust-dropbox.git)
    cd zero-trust-dropbox
    ```

2.  **Create Virtual Environment:**
    ```bash
    python -m venv venv
    venv\Scripts\activate # Windows
    # source venv/bin/activate # macOS/Linux
    ```

3.  **Install Requirements:**
    ```bash
    pip install Flask PyJWT cryptography requests pyotp geoip2 ttkbootstrap
    ```

4.  **Download Geolocation Database:**
    * Download the `GeoLite2-Country.mmdb` file from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data?lang=en) (or use the direct link: `https://git.io/GeoLite2-Country.mmdb`).
    * Unzip it and place the `.mmdb` file in the **root** project folder (`zero-trust-dropbox/`).

5.  **Generate Device Keys:**
    * Run the script to create your device's identity:
        ```bash
        python register_device.py
        ```
    * This creates `device_private_key.pem` (keep secret!) and `device_public_key.pem`.

6.  **Configure Server:**
    * Open `server/server.py`.
    * **Paste MFA Secret:** If you haven't already, generate an MFA secret key (using a tool or `generate_key.py` if included) and paste it into the `mfa_secret` field in the `USERS` dictionary.
    * **Paste Device Public Key:** Open `device_public_key.pem`, copy its *entire* content, and paste it into the `device_public_key` field in the `USERS` dictionary within `server/server.py`.
    * **Set Allowed Country:** Verify the `allowed_country` is set correctly (e.g., `"IN"`).

7.  **Set Up Authenticator App:**
    * Install an authenticator app (like Google Authenticator) on your phone.
    * Manually add a new account using the `mfa_secret` key you configured in the server.

## ▶️ Running the Application

You need two separate command prompts/terminals.

1.  **Start the Server:**
    ```bash
    cd C:\Users\Shresth\zero-trust-dropbox # Or your path
    venv\Scripts\activate
    python server/server.py
    ```

2.  **Launch the Client:**
    ```bash
    cd C:\Users\Shresth\zero-trust-dropbox # Or your path
    venv\Scripts\activate
    python client/client_gui.py
    ```

3.  **Log In:** Enter your username (`G7`), password (`welcomepanel7`), and the current 6-digit code from your authenticator app.

You can now upload (encrypted), download (decrypted), and manage files securely!
