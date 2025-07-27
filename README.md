
# Secure Command-Line Password Vault with Auditing

This project is a robust, command-line interface (CLI) password manager designed to securely store and manage sensitive credentials. It leverages modern cryptographic primitives to ensure data confidentiality and integrity, while also providing a comprehensive auditing mechanism to log all significant actions. Built with a focus on simplicity and security, it allows users to keep their passwords, API keys, and other secrets protected and easily accessible.

---

## ✨ Features

- **Strong Encryption:** Utilizes AES-GCM (Authenticated Encryption with Associated Data in Galois/Counter Mode) to provide confidentiality and integrity for stored vault data.
- **Secure Key Derivation:** Employs PBKDF2HMAC with a cryptographically secure salt to derive keys from the user's master password, resisting brute-force and dictionary attacks.
- **Data Persistence:** Stores encrypted credentials and salts securely in a `vault.json` file, preserving data across sessions.
- **Auditing and Logging:** Logs all major vault operations (adding, retrieving, deleting entries) with timestamps in an `audit.log` file for transparency and accountability.
- **Clipboard Integration:** Copies sensitive information to the system clipboard with automatic clearing after a short delay to minimize data exposure.
- **Command-Line Interface (CLI):** Provides an intuitive terminal-based interface for vault interactions.
- **Master Password Protection:** Enforces a secure master password entry via `getpass`, never storing the master password itself.

---

## 🧠 How it Works

- **Initialization:**  
  On first run, prompts the user to set a master password and generates a unique salt; these are used to derive the encryption key and initialize an empty vault.

- **Encryption & Decryption:**  
  Vault entries (service name, username, password) are encrypted and decrypted transparently using the derived key when adding or retrieving entries.

- **Key Derivation:**  
  Each execution derives the encryption key deterministically from the master password and stored salt using PBKDF2HMAC, ensuring the master password is never saved.

- **Auditing:**  
  Every significant command triggers a logging function that appends a timestamped record to `audit.log`, creating an immutable activity trail separate from the encrypted vault.

---

## 💻 Technologies Used

- **Python:** Core programming language.
- **cryptography:** Provides PBKDF2HMAC for key derivation and AESGCM for authenticated encryption.
- **pyperclip:** Cross-platform clipboard access module.
- **getpass:** For secure, non-echoed master password input.
- **json:** File format handling for vault data.
- **os, re, time, datetime, secrets, string:** Standard libraries for filesystem operations, input validation, time management, secure randomness, and string manipulation.

---

## 📁 Project Structure

```
computer-security/
├── main.py        # Main script implementing the vault logic and CLI
├── vault.json     # Encrypted vault data file (created at first use)
├── audit.log      # Audit log file recording all vault operations (created at first use)
└── README.md      # Project documentation (this file)
```

---

## ⚙️ Setup and Installation

1. **Clone the Repository:**

   ```
   git clone 
   cd computer-security
   ```

2. **Install Dependencies:**

   ```
   pip install cryptography pyperclip
   ```

   *(Note: `getpass` and standard modules are included with Python.)*

---

## ▶️ Usage

All interactions occur via the command line.

### Initialize the Vault (First Time Use):

Run the application, which will prompt to set up your master password:

```
python main.py
```

This creates `vault.json` and `audit.log`.

### Adding a New Entry:

```
python main.py add
```

- Enter your master password, service name (e.g., "google"), username, and password.

### Retrieving an Entry:

```
python main.py get
```

- Enter your master password and service name.
- Displays the username and password.
- Copies the password to clipboard (cleared automatically after 10 seconds).

### Listing All Entries:

```
python main.py list
```

- Enter your master password to view all stored service names.

### Deleting an Entry:

```
python main.py delete
```

- Enter your master password and the service name to remove an entry.

### Viewing the Audit Log:

Audit logs can be inspected directly:

```
cat audit.log
```

---

## 🔒 Security Considerations

- **Master Password Strength:**  
  Use a long, complex, and unique master password to ensure vault security.

- **Physical Security:**  
  Secure `vault.json` and `audit.log` files on disk, since unauthorized access could still pose risks.

- **Clipboard Exposure:**  
  Clipboard contents clear automatically but remain briefly exposed; avoid using the get command on shared systems.

- **Auditing for Accountability:**  
  The `audit.log` tracks successful and failed vault accesses, enabling monitoring of unauthorized attempts.

---

## 💡 Conclusion

This Secure Command-Line Password Vault delivers a powerful and transparent solution for managing digital credentials safely. By combining cutting-edge encryption with comprehensive auditing and practical clipboard handling, it empowers users to maintain strict control over sensitive information. It serves as a strong example of applying cryptographic best practices to tangible security problems, suitable for both personal use and as an educational foundation in cybersecurity development.

