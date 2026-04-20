Project title
SecureShare – Secure File and Text Sharing Application

What the project is
A full-stack web prototype for encrypted text and file sharing using client-side cryptography, JWT authentication and ciphertext-only backend storage.

Tech stack

* Frontend: React + Vite
* Backend: Node.js + Express
* Database: MongoDB
* Cryptography: Web Crypto API, AES-GCM, RSA-OAEP

Requirements

* Node.js installed
* npm installed
* MongoDB connection string
* modern browser

Setup steps

1. Extract the ZIP.
2. Open terminal in backend.
3. Run npm install.
4. Create .env file based on .env.example.
5. Add MongoDB connection string and JWT secret.
6. Run backend with npm run dev.
7. Open terminal in frontend.
8. Run npm install.
9. Run npm run dev.
10. Open the local frontend URL shown in terminal.

Important notes

* Private keys are stored locally in the browser for prototype purposes.
* Use separate browsers or profiles to simulate different users.
* MongoDB stores ciphertext, encrypted AES key, IV and metadata rather than plaintext content.

Demo workflow

* Register user A and user B
* log in as user A
* generate RSA keys
* send encrypted text/file to user B
* log in as user B in separate browser/profile
* load inbox and decrypt
* use attacker demo with wrong key and then correct key