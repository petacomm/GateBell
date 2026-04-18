<div align="center">
  <img src="https://gatebell.kotechsoft.com/logo.png" alt="Kotech Petacomm" height="80">
  <h1>GateBell</h1>
  <p><strong>SSH Login Detector & Announcer</strong></p>
  <p>A <a href="https://kotechsoft.com">Kotech Petacomm</a> Product</p>

  ![Version](https://img.shields.io/badge/version-1.0.0-blue)
  ![License](https://img.shields.io/badge/license-GPLv3-green)
  ![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)
  ![Python](https://img.shields.io/badge/python-3.8%2B-blue)
</div>

---

## What is GateBell?

GateBell watches your Linux server 24/7. Every time someone connects via SSH, you get an instant email alert with:

- **Connecting IP address**
- **Country, city & ISP** — powered by ip-api.com
- **Date & time** of the login
- **Server nickname** so you know which server was accessed

No dashboards. No subscriptions. No complexity.
**One command to install. Two minutes to set up.**

---

## Quick Install

```bash
curl -fsSL https://repo.kotechsoft.com/gbi.sh | sudo bash
```

Then run the setup wizard:

```bash
sudo gatebell-setup
```

The wizard will:
1. Ask for your email address
2. Send you a 6-digit verification code
3. Ask you to give this server a nickname
4. Automatically connect GateBell to SSH

That's it. No config files to edit.

---

## How It Works

```
Someone connects via SSH
        │
        ▼
Linux PAM detects the session
        │
        ▼
GateBell captures IP & timestamp
        │
        ▼
Signed HMAC request → Kotech Petacomm API
        │
        ▼
IP analyzed (Country, City, ISP)
        │
        ▼
Email alert sent to your inbox
```

GateBell uses **Linux PAM** (Pluggable Authentication Modules) to detect SSH logins at the authentication layer — the most reliable method available.

SSH connections are **never delayed or interrupted**. The notification runs in the background.

---

## Security

GateBell was built with security as a first priority:

| Feature | Details |
|---|---|
| **Per-user HMAC-SHA256** | Every client has a unique secret key — no shared secrets |
| **Replay attack protection** | Each request includes a nonce + 5-minute timestamp window |
| **Hashed secrets** | Client secrets are stored as SHA-256 hashes, never plaintext |
| **No information leakage** | Error responses never reveal whether an email exists |
| **PAM integration** | Hooks into the Linux authentication layer directly |
| **TLS everywhere** | All communication over HTTPS |

---

## Requirements

- Ubuntu 20.04+ or Debian 11+
- Python 3.8+
- OpenSSH server
- Internet connection
- Root / sudo access

---

## Manual APT Install

If you prefer to add the repository manually:

```bash
# Add GPG key
curl -fsSL https://repo.kotechsoft.com/kotech-petacomm.gpg | \
  sudo gpg --dearmor -o /usr/share/keyrings/kotech-petacomm.gpg

# Add repository
echo "deb [signed-by=/usr/share/keyrings/kotech-petacomm.gpg] \
  https://repo.kotechsoft.com stable main" | \
  sudo tee /etc/apt/sources.list.d/gatebell.list

# Install
sudo apt update && sudo apt install gatebell
```

---

## Project Structure

```
gatebell/
├── app.py              # Flask API server (runs on Kotech Petacomm infrastructure)
├── requirements.txt    # Python dependencies
├── gatebell.service    # systemd service file
├── gatebell-setup      # Client setup wizard
├── gatebell-notify     # PAM notifier script
├── gatebell-pam        # PAM wrapper
└── gbsetup.sh          # One-line installer
```

---

## Self-Hosting

Want to run your own GateBell server? The full server code is in `app.py`.

Requirements:
- Python 3.8+
- Flask, flask-limiter, python-dotenv
- A Brevo (or any SMTP) account for sending emails
- A domain with SSL

See `.env.example` for configuration options.

---

## License

GateBell is free and open source software, released under the **GNU General Public License v3.0**.

See [LICENSE](LICENSE) for details.

---

## Support

- Website: [kotechsoft.com](https://kotechsoft.com)
- Email: [support@kotechsoft.com](mailto:support@kotechsoft.com)
- Issues: [GitHub Issues](https://github.com/petacomm/GateBell/issues)

---

<div align="center">
  <sub>Built with care by <strong>Kotech Petacomm</strong> — secure tools for everyone.</sub>
</div>
