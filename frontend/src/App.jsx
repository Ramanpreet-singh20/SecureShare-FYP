import { useState } from "react";

const API_BASE = "http://localhost:5000";

// ----- Helper functions: crypto + base64 -----

async function generateRsaKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );

  const publicJwk = await window.crypto.subtle.exportKey(
    "jwk",
    keyPair.publicKey
  );
  const privateJwk = await window.crypto.subtle.exportKey(
    "jwk",
    keyPair.privateKey
  );

  return { publicJwk, privateJwk };
}

function savePrivateKeyToLocalStorage(privateJwk) {
  localStorage.setItem("secureshare_private_key", JSON.stringify(privateJwk));
}

function loadPrivateKeyFromLocalStorage() {
  const raw = localStorage.getItem("secureshare_private_key");
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function clearPrivateKeyFromLocalStorage() {
  localStorage.removeItem("secureshare_private_key");
}

function bufToBase64(arrayBuffer) {
  const bytes = new Uint8Array(arrayBuffer);
  let binary = "";
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return window.btoa(binary);
}

function base64ToBuf(b64) {
  const binary = window.atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Simple validation helpers
function isValidEmail(email) {
  return /\S+@\S+\.\S+/.test(email);
}

function isStrongPassword(password) {
  return typeof password === "string" && password.length >= 8;
}

// Import public key from JWK to CryptoKey
async function importRecipientPublicKey(publicJwk) {
  return window.crypto.subtle.importKey(
    "jwk",
    publicJwk,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["encrypt"]
  );
}

// Import private key (from localStorage JWK) to CryptoKey
async function getPrivateKeyCryptoKey() {
  const jwk = loadPrivateKeyFromLocalStorage();
  if (!jwk) {
    throw new Error("No private key in localStorage");
  }

  return window.crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["decrypt"]
  );
}

// Encrypt plaintext for recipient using hybrid RSA + AES-GCM (TEXT)
async function encryptForRecipient(publicJwk, plaintext) {
  const publicKey = await importRecipientPublicKey(publicJwk);

  const aesKey = await window.crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  );

  const encoder = new TextEncoder();
  const data = encoder.encode(plaintext);

  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  const ciphertextBuf = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    aesKey,
    data
  );

  const aesRaw = await window.crypto.subtle.exportKey("raw", aesKey);

  const encryptedKeyBuf = await window.crypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
    },
    publicKey,
    aesRaw
  );

  const ciphertext = bufToBase64(ciphertextBuf);
  const encryptedKey = bufToBase64(encryptedKeyBuf);
  const ivB64 = bufToBase64(iv.buffer);

  return { ciphertext, encryptedKey, iv: ivB64 };
}

// Decrypt a text share using the private key
async function decryptShareWithPrivateKey(share) {
  const privateKey = await getPrivateKeyCryptoKey();

  const encryptedKeyBuf = base64ToBuf(share.encryptedKey);
  const aesRaw = await window.crypto.subtle.decrypt(
    {
      name: "RSA-OAEP",
    },
    privateKey,
    encryptedKeyBuf
  );

  const aesKey = await window.crypto.subtle.importKey(
    "raw",
    aesRaw,
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["decrypt"]
  );

  const ivBuf = base64ToBuf(share.iv);
  const ciphertextBuf = base64ToBuf(share.ciphertext);

  const plainBuf = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: new Uint8Array(ivBuf),
    },
    aesKey,
    ciphertextBuf
  );

  const decoder = new TextDecoder();
  return decoder.decode(plainBuf);
}

// Encrypt raw bytes (ArrayBuffer) for recipient (FILES)
async function encryptBytesForRecipient(publicJwk, arrayBuffer) {
  const publicKey = await importRecipientPublicKey(publicJwk);

  const aesKey = await window.crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  );

  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  const ciphertextBuf = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    aesKey,
    arrayBuffer
  );

  const aesRaw = await window.crypto.subtle.exportKey("raw", aesKey);

  const encryptedKeyBuf = await window.crypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
    },
    publicKey,
    aesRaw
  );

  const ciphertext = bufToBase64(ciphertextBuf);
  const encryptedKey = bufToBase64(encryptedKeyBuf);
  const ivB64 = bufToBase64(iv.buffer);

  return { ciphertext, encryptedKey, iv: ivB64 };
}

// Decrypt to bytes (ArrayBuffer) for files
async function decryptShareToBytes(share) {
  const privateKey = await getPrivateKeyCryptoKey();

  const encryptedKeyBuf = base64ToBuf(share.encryptedKey);
  const aesRaw = await window.crypto.subtle.decrypt(
    {
      name: "RSA-OAEP",
    },
    privateKey,
    encryptedKeyBuf
  );

  const aesKey = await window.crypto.subtle.importKey(
    "raw",
    aesRaw,
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["decrypt"]
  );

  const ivBuf = base64ToBuf(share.iv);
  const ciphertextBuf = base64ToBuf(share.ciphertext);

  const plainBuf = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: new Uint8Array(ivBuf),
    },
    aesKey,
    ciphertextBuf
  );

  return plainBuf; // ArrayBuffer
}

// ----- Main React component -----

function App() {
  const [mode, setMode] = useState("login");
  const [email, setEmail] = useState("test1@example.com");
  const [password, setPassword] = useState("Pass1234!");
  const [message, setMessage] = useState("");
  const [token, setToken] = useState("");
  const [me, setMe] = useState(null);
  const [hasKeys, setHasKeys] = useState(() => !!loadPrivateKeyFromLocalStorage());
  const [showPassword, setShowPassword] = useState(false);

  // For sending encrypted text messages
  const [targetEmail, setTargetEmail] = useState("");
  const [messageText, setMessageText] = useState("");
  const [isSending, setIsSending] = useState(false);

  // Expiry times (minutes)
  const [textExpiryMinutes, setTextExpiryMinutes] = useState(60);
  const [fileExpiryMinutes, setFileExpiryMinutes] = useState(60);

  // Inbox
  const [inbox, setInbox] = useState([]);
  const [isLoadingInbox, setIsLoadingInbox] = useState(false);

  // Sent items
  const [sentItems, setSentItems] = useState([]);
  const [isLoadingSent, setIsLoadingSent] = useState(false);

  // For sending encrypted files
  const [fileRecipientEmail, setFileRecipientEmail] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);
  const [isSendingFile, setIsSendingFile] = useState(false);

  // For decrypted file download URLs
  const [fileUrls, setFileUrls] = useState({}); // { shareId: objectUrl }


const [attackerCiphertext, setAttackerCiphertext] = useState("");
const [attackerEncryptedKey, setAttackerEncryptedKey] = useState("");
const [attackerIv, setAttackerIv] = useState("");
const [attackerResult, setAttackerResult] = useState("");

  async function handleRegister(e) {
    e.preventDefault();

    if (!isValidEmail(email)) {
      setMessage("Please enter a valid email address.");
      return;
    }

    if (!isStrongPassword(password)) {
      setMessage("Password must be at least 8 characters long.");
      return;
    }

    setMessage("Registering...");

    try {
      const res = await fetch(`${API_BASE}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json();
      if (!res.ok) {
        setMessage(`Error: ${data.message || "Failed to register"}`);
        return;
      }

      setMessage(`✅ Registered: ${data.message}`);
    } catch (err) {
      console.error(err);
      setMessage("Error: could not reach server");
    }
  }

  async function handleDeleteShare(shareId) {
    if (!token) {
      setMessage("You must be logged in to delete shares.");
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/shares/${shareId}`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const data = await res.json();
      if (!res.ok) {
        setMessage(`Error deleting share: ${data.message || "Unknown error"}`);
        return;
      }

      setInbox((prev) => prev.filter((s) => s.id !== shareId));
      setSentItems((prev) => prev.filter((s) => s.id !== shareId));
      setMessage("✅ Share deleted.");
    } catch (err) {
      console.error(err);
      setMessage("Error: could not delete share.");
    }
  }

  async function handleLogin(e) {
    e.preventDefault();

    if (!isValidEmail(email)) {
      setMessage("Please enter a valid email address.");
      return;
    }

    if (!password) {
      setMessage("Password is required.");
      return;
    }

    setMessage("Logging in...");

    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json();
      if (!res.ok) {
        setMessage(`Error: ${data.message || "Failed to login"}`);
        return;
      }

      setToken(data.token);
      setMessage("✅ Logged in, token stored in memory.");
      setMe(null);
    } catch (err) {
      console.error(err);
      setMessage("Error: could not reach server");
    }
  }

  async function handleMe() {
    if (!token) {
      setMessage("No token — please login first.");
      return;
    }

    setMessage("Fetching /auth/me...");

    try {
      const res = await fetch(`${API_BASE}/auth/me`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const data = await res.json();
      if (!res.ok) {
        setMessage(`Error: ${data.message || "Failed to fetch user"}`);
        setMe(null);
        return;
      }

      setMe(data.user);
      setMessage("✅ /auth/me successful.");
    } catch (err) {
      console.error(err);
      setMessage("Error: could not reach server");
    }
  }

  function handleLogout() {
    setToken("");
    setMe(null);
    setMessage("Logged out.");
  }

  function handleResetKeys() {
    clearPrivateKeyFromLocalStorage();
    setHasKeys(false);
    setMessage(
      "Local encryption keys removed from this device. " +
        "You can generate new keys again with 'Setup RSA keys (E2EE)'."
    );
  }

  async function handleSetupKeys() {
    if (!token) {
      setMessage("You must be logged in to setup keys.");
      return;
    }

    setMessage("Generating RSA key pair...");

    try {
      const { publicJwk, privateJwk } = await generateRsaKeyPair();

      savePrivateKeyToLocalStorage(privateJwk);

      const res = await fetch(`${API_BASE}/auth/public-key`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ publicKey: publicJwk }),
      });

      const data = await res.json();

      if (!res.ok) {
        setMessage(`Error saving public key: ${data.message || "Unknown error"}`);
        return;
      }

      setHasKeys(true);
      setMessage("✅ RSA keypair generated and public key saved.");
    } catch (err) {
      console.error(err);
      setMessage("Error: failed to generate or save keys.");
    }
  }

  async function fetchRecipientPublicKey(recipientEmail) {
    const res = await fetch(
      `${API_BASE}/auth/public-key/${encodeURIComponent(recipientEmail)}`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || "Failed to fetch recipient public key");
    }

    return data.publicKey;
  }

  async function handleSendEncrypted(e) {
    e.preventDefault();
    if (!token) {
      setMessage("You must be logged in to send encrypted messages.");
      return;
    }
    if (!hasKeys) {
      setMessage("You must generate your keys first.");
      return;
    }
    if (!targetEmail || !messageText.trim()) {
      setMessage("Recipient email and message text are required.");
      return;
    }

    setIsSending(true);
    setMessage("Encrypting and sending...");

    try {
      const publicJwk = await fetchRecipientPublicKey(targetEmail);

      const { ciphertext, encryptedKey, iv } = await encryptForRecipient(
        publicJwk,
        messageText.trim()
      );

      const res = await fetch(`${API_BASE}/shares`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          recipientEmail: targetEmail,
          ciphertext,
          encryptedKey,
          iv,
          expiresInMinutes: Number(textExpiryMinutes) || 60,
          isFile: false,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        setMessage(
          `Error sending encrypted message: ${data.message || "Unknown error"}`
        );
        setIsSending(false);
        return;
      }

      setMessage("✅ Encrypted message stored on server.");
      setMessageText("");
    } catch (err) {
      console.error(err);
      setMessage(`Error: ${err.message}`);
    } finally {
      setIsSending(false);
    }
  }

  async function handleLoadInbox() {
    if (!token) {
      setMessage("You must be logged in to load inbox.");
      return;
    }

    setIsLoadingInbox(true);
    setMessage("Loading inbox...");

    try {
      const res = await fetch(`${API_BASE}/shares/inbox`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const data = await res.json();
      if (!res.ok) {
        setMessage(`Error loading inbox: ${data.message || "Unknown error"}`);
        setIsLoadingInbox(false);
        return;
      }

      setInbox(data.inbox || []);
      setMessage("✅ Inbox loaded.");
    } catch (err) {
      console.error(err);
      setMessage("Error: could not load inbox.");
    } finally {
      setIsLoadingInbox(false);
    }
  }

  async function handleLoadSentItems() {
    if (!token) {
      setMessage("You must be logged in to load sent items.");
      return;
    }

    setIsLoadingSent(true);
    setMessage("Loading sent items...");

    try {
      const res = await fetch(`${API_BASE}/shares/sent`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const data = await res.json();
      if (!res.ok) {
        setMessage(`Error loading sent items: ${data.message || "Unknown error"}`);
        return;
      }

      setSentItems(data.sent || []);
      setMessage("✅ Sent items loaded.");
    } catch (err) {
      console.error(err);
      setMessage("Error: could not load sent items.");
    } finally {
      setIsLoadingSent(false);
    }
  }

  async function handleDecryptShare(shareId) {
    try {
      const share = inbox.find((s) => s.id === shareId);
      if (!share) {
        setMessage("Share not found in inbox.");
        return;
      }

      const plaintext = await decryptShareWithPrivateKey(share);

      const updated = inbox.map((s) =>
        s.id === shareId ? { ...s, decryptedText: plaintext } : s
      );
      setInbox(updated);
      setMessage("✅ Share decrypted locally in browser.");
    } catch (err) {
      console.error(err);
      setMessage(`Error decrypting share: ${err.message}`);
    }
  }

  async function handleAttackerDecrypt() {
    setAttackerResult("");
  
    if (!attackerCiphertext || !attackerEncryptedKey || !attackerIv) {
      setAttackerResult("Please paste ciphertext, encryptedKey, and iv.");
      return;
    }
  
    try {
      const fakeShare = {
        ciphertext: attackerCiphertext.trim(),
        encryptedKey: attackerEncryptedKey.trim(),
        iv: attackerIv.trim(),
      };
  
      const plaintext = await decryptShareWithPrivateKey(fakeShare);
  
      setAttackerResult(`⚠️ Unexpected success: ${plaintext}`);
    } catch (err) {
      console.error("Attacker decrypt failed as expected:", err);
      setAttackerResult(
        `✅ Decryption failed as expected. This device does not have the correct private key.`
      );
    }
  }

  async function handleSendFile(e) {
    e.preventDefault();

    if (!token) {
      setMessage("You must be logged in to send files.");
      return;
    }
    if (!hasKeys) {
      setMessage("You must generate your keys first.");
      return;
    }
    if (!fileRecipientEmail || !selectedFile) {
      setMessage("Recipient email and a file are required.");
      return;
    }

    setIsSendingFile(true);
    setMessage("Encrypting file and sending...");

    try {
      const publicJwk = await fetchRecipientPublicKey(fileRecipientEmail);

      const arrayBuffer = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = (err) => reject(err);
        reader.readAsArrayBuffer(selectedFile);
      });

      const { ciphertext, encryptedKey, iv } = await encryptBytesForRecipient(
        publicJwk,
        arrayBuffer
      );

      const res = await fetch(`${API_BASE}/shares`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          recipientEmail: fileRecipientEmail,
          ciphertext,
          encryptedKey,
          iv,
          isFile: true,
          fileName: selectedFile.name,
          fileType: selectedFile.type || "application/octet-stream",
          fileSize: selectedFile.size,
          expiresInMinutes: Number(fileExpiryMinutes) || 60,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        setMessage(
          `Error sending encrypted file: ${data.message || "Unknown error"}`
        );
        setIsSendingFile(false);
        return;
      }

      setMessage("✅ Encrypted file stored on server.");
      setSelectedFile(null);
      setFileRecipientEmail("");
    } catch (err) {
      console.error(err);
      setMessage(`Error sending file: ${err.message}`);
    } finally {
      setIsSendingFile(false);
    }
  }

  async function handleDecryptFile(shareId) {
    try {
      const share = inbox.find((s) => s.id === shareId);
      if (!share) {
        setMessage("Share not found in inbox.");
        return;
      }
      if (!share.isFile) {
        setMessage("This share is not marked as a file.");
        return;
      }

      const plainBuf = await decryptShareToBytes(share);

      const blob = new Blob([plainBuf], {
        type: share.fileType || "application/octet-stream",
      });
      const url = URL.createObjectURL(blob);

      setFileUrls((prev) => ({
        ...prev,
        [shareId]: url,
      }));

      setMessage("✅ File decrypted locally. You can download it now.");
    } catch (err) {
      console.error(err);
      setMessage(`Error decrypting file: ${err.message}`);
    }
  }

  // ---------- VIEW 1: NOT LOGGED IN (only login/register) ----------
  if (!token) {
    return (
      <div style={styles.container}>
        <div style={styles.card}>
          <h1>SecureShare – Encrypted Sharing Demo</h1>

          <div style={styles.tabRow}>
            <button
              style={{
                ...styles.tabButton,
                ...(mode === "login" ? styles.tabButtonActive : {}),
              }}
              onClick={() => setMode("login")}
            >
              Login
            </button>
            <button
              style={{
                ...styles.tabButton,
                ...(mode === "register" ? styles.tabButtonActive : {}),
              }}
              onClick={() => setMode("register")}
            >
              Register
            </button>
          </div>

          <form
            onSubmit={mode === "login" ? handleLogin : handleRegister}
            style={styles.form}
          >
            <label style={styles.label}>
              Email
              <input
                style={styles.input}
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </label>

            <label style={styles.label}>
              Password
              <div style={styles.inputWrapper}>
                <input
                  style={{ ...styles.input, paddingRight: "60px" }}
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
                <button
                  type="button"
                  style={styles.eyeButton}
                  onClick={() => setShowPassword((prev) => !prev)}
                >
                  {showPassword ? "Hide" : "Show"}
                </button>
              </div>
            </label>

            <button type="submit" style={styles.primaryButton}>
              {mode === "login" ? "Login" : "Register"}
            </button>
          </form>

          <div style={styles.messageBox}>{message}</div>
        </div>
      </div>
    );
  }

  // ---------- VIEW 2: LOGGED IN (main sharing UI) ----------
  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h1>SecureShare – Encrypted Sharing Demo</h1>

        <div
          style={{
            marginTop: "8px",
            marginBottom: "12px",
            display: "flex",
            flexDirection: "column",
            gap: "8px",
          }}
        >
          <div style={{ fontSize: "0.9rem", color: "#9ca3af" }}>
            Logged in as: <strong>{me?.email || email}</strong>
          </div>
          <div style={{ display: "flex", gap: "8px" }}>
            <button
              type="button"
              style={styles.secondaryButton}
              onClick={handleMe}
            >
              Refresh /auth/me
            </button>
            <button
              type="button"
              style={styles.secondaryButton}
              onClick={handleLogout}
            >
              Logout
            </button>
          </div>
        </div>

        <div style={{ marginTop: "4px" }}>
          <button
            type="button"
            style={styles.secondaryButton}
            onClick={handleSetupKeys}
          >
            Setup RSA keys (E2EE)
          </button>
          {hasKeys && (
            <>
              <div
                style={{
                  marginTop: "4px",
                  fontSize: "0.8rem",
                  color: "#22c55e",
                }}
              >
                ✓ Keys present on this device
              </div>
              <button
                type="button"
                style={{ ...styles.secondaryButton, marginTop: "4px" }}
                onClick={handleResetKeys}
              >
                Remove keys from this device
              </button>
            </>
          )}
        </div>

        <hr style={{ margin: "20px 0", borderColor: "#1f2937" }} />
        <h2 style={{ fontSize: "1rem", marginBottom: "8px" }}>
          Send Encrypted Message
        </h2>
        <form onSubmit={handleSendEncrypted} style={styles.form}>
          <label style={styles.label}>
            Recipient email
            <input
              style={styles.input}
              type="email"
              value={targetEmail}
              onChange={(e) => setTargetEmail(e.target.value)}
            />
          </label>

          <label style={styles.label}>
            Message text
            <textarea
              style={{ ...styles.input, minHeight: "60px" }}
              value={messageText}
              onChange={(e) => setMessageText(e.target.value)}
            />
          </label>

          <label style={styles.label}>
            Expires in (minutes)
            <input
              style={styles.input}
              type="number"
              min="1"
              max="1440"
              value={textExpiryMinutes}
              onChange={(e) => setTextExpiryMinutes(e.target.value)}
            />
          </label>

          <button
            type="submit"
            style={styles.primaryButton}
            disabled={isSending}
          >
            {isSending ? "Sending..." : "Send Encrypted"}
          </button>
        </form>

        <hr style={{ margin: "20px 0", borderColor: "#1f2937" }} />
        <h2 style={{ fontSize: "1rem", marginBottom: "8px" }}>
          Send Encrypted File
        </h2>
        <form onSubmit={handleSendFile} style={styles.form}>
          <label style={styles.label}>
            Recipient email
            <input
              style={styles.input}
              type="email"
              value={fileRecipientEmail}
              onChange={(e) => setFileRecipientEmail(e.target.value)}
            />
          </label>

          <label style={styles.label}>
            Choose file
            <input
              style={styles.input}
              type="file"
              onChange={(e) => setSelectedFile(e.target.files[0] || null)}
            />
          </label>

          {selectedFile && (
            <div style={{ fontSize: "0.8rem", color: "#9ca3af" }}>
              Selected: {selectedFile.name} (
              {Math.round(selectedFile.size / 1024)} KB)
            </div>
          )}

          <label style={styles.label}>
            Expires in (minutes)
            <input
              style={styles.input}
              type="number"
              min="1"
              max="1440"
              value={fileExpiryMinutes}
              onChange={(e) => setFileExpiryMinutes(e.target.value)}
            />
          </label>

          <button
            type="submit"
            style={styles.primaryButton}
            disabled={isSendingFile}
          >
            {isSendingFile ? "Sending file..." : "Send Encrypted File"}
          </button>
        </form>

        <hr style={{ margin: "20px 0", borderColor: "#1f2937" }} />
        <h2 style={{ fontSize: "1rem", marginBottom: "8px" }}>Inbox</h2>
        <button
          type="button"
          style={styles.secondaryButton}
          onClick={handleLoadInbox}
          disabled={isLoadingInbox}
        >
          {isLoadingInbox ? "Loading..." : "Load Inbox"}
        </button>

        {inbox.length > 0 && (
          <div
            style={{
              marginTop: "12px",
              maxHeight: "200px",
              overflowY: "auto",
            }}
          >
            {inbox.map((share) => {
              const isExpired =
                share.isExpired ||
                (share.expiresAt && new Date(share.expiresAt) < new Date());

              const cardStyle = {
                ...styles.shareCard,
                opacity: isExpired ? 0.6 : 1,
                borderColor: isExpired ? "#4b5563" : "#1f2937",
              };

              return (
                <div key={share.id} style={cardStyle}>
                  <div style={{ fontSize: "0.85rem" }}>
                    <strong>From:</strong> {share.senderEmail}
                  </div>
                  <div style={{ fontSize: "0.75rem", color: "#9ca3af" }}>
                    {new Date(share.createdAt).toLocaleString()}
                    {share.expiresAt && (
                      <>
                        {" · "}
                        Expires: {new Date(share.expiresAt).toLocaleString()}
                      </>
                    )}
                    {isExpired && (
                      <span style={{ marginLeft: "4px", color: "#f97316" }}>
                        (Expired)
                      </span>
                    )}
                  </div>

                  {share.isFile ? (
                    <>
                      <div style={{ marginTop: "6px", fontSize: "0.9rem" }}>
                        <strong>Encrypted file:</strong>{" "}
                        {share.fileName || "Unnamed file"}{" "}
                        {share.fileSize != null &&
                          `(${Math.round(share.fileSize / 1024)} KB)`}
                      </div>

                      {fileUrls[share.id] ? (
                        <a
                          href={fileUrls[share.id]}
                          download={share.fileName || "download"}
                          style={{
                            ...styles.secondaryButton,
                            marginTop: "6px",
                            display: "inline-block",
                            textAlign: "center",
                            textDecoration: "none",
                          }}
                        >
                          Download decrypted file
                        </a>
                      ) : (
                        <button
                          type="button"
                          style={{
                            ...styles.secondaryButton,
                            marginTop: "6px",
                          }}
                          onClick={() => handleDecryptFile(share.id)}
                          disabled={isExpired}
                        >
                          Decrypt file
                        </button>
                      )}
                    </>
                  ) : (
                    <>
                      {share.decryptedText ? (
                        <div style={{ marginTop: "6px", fontSize: "0.9rem" }}>
                          <strong>Decrypted:</strong> {share.decryptedText}
                        </div>
                      ) : (
                        <div style={{ marginTop: "6px", fontSize: "0.8rem" }}>
                          <em>Encrypted message (ciphertext not shown)</em>
                        </div>
                      )}

                      <button
                        type="button"
                        style={{
                          ...styles.secondaryButton,
                          marginTop: "6px",
                        }}
                        onClick={() => handleDecryptShare(share.id)}
                        disabled={isExpired}
                      >
                        Decrypt message
                      </button>
                    </>
                  )}

                  <button
                    type="button"
                    style={{
                      ...styles.secondaryButton,
                      marginTop: "6px",
                      borderColor: "#b91c1c",
                    }}
                    onClick={() => handleDeleteShare(share.id)}
                  >
                    Delete
                  </button>
                </div>
              );
            })}
          </div>
        )}

        {/* Sent Items */}
        <hr style={{ margin: "20px 0", borderColor: "#1f2937" }} />
        <h2 style={{ fontSize: "1rem", marginBottom: "8px" }}>Sent Items</h2>
        <button
          type="button"
          style={styles.secondaryButton}
          onClick={handleLoadSentItems}
          disabled={isLoadingSent}
        >
          {isLoadingSent ? "Loading..." : "Load Sent Items"}
        </button>

        {sentItems.length > 0 && (
          <div
            style={{
              marginTop: "12px",
              maxHeight: "200px",
              overflowY: "auto",
            }}
          >
            {sentItems.map((share) => {
              const isExpired =
                share.isExpired ||
                (share.expiresAt && new Date(share.expiresAt) < new Date());

              const cardStyle = {
                ...styles.shareCard,
                opacity: isExpired ? 0.6 : 1,
                borderColor: isExpired ? "#4b5563" : "#1f2937",
              };

              return (
                <div key={share.id} style={cardStyle}>
                  <div style={{ fontSize: "0.85rem" }}>
                    <strong>To:</strong> {share.recipientEmail}
                  </div>
                  <div style={{ fontSize: "0.75rem", color: "#9ca3af" }}>
                    {new Date(share.createdAt).toLocaleString()}
                    {share.expiresAt && (
                      <>
                        {" · "}
                        Expires: {new Date(share.expiresAt).toLocaleString()}
                      </>
                    )}
                    {isExpired && (
                      <span style={{ marginLeft: "4px", color: "#f97316" }}>
                        (Expired)
                      </span>
                    )}
                  </div>

                  {share.isFile ? (
                    <div style={{ marginTop: "6px", fontSize: "0.9rem" }}>
                      <strong>File share:</strong>{" "}
                      {share.fileName || "Unnamed file"}{" "}
                      {share.fileSize != null &&
                        `(${Math.round(share.fileSize / 1024)} KB)`}
                    </div>
                  ) : (
                    <div style={{ marginTop: "6px", fontSize: "0.8rem" }}>
                      <em>Encrypted text message</em>
                    </div>
                  )}

                  <button
                    type="button"
                    style={{
                      ...styles.secondaryButton,
                      marginTop: "6px",
                      borderColor: "#b91c1c",
                    }}
                    onClick={() => handleDeleteShare(share.id)}
                  >
                    Delete
                  </button>
                </div>
              );
            })}
          </div>
        )}

                {/* Attacker Demo */}
                <hr style={{ margin: "20px 0", borderColor: "#1f2937" }} />
        <h2 style={{ fontSize: "1rem", marginBottom: "8px" }}>
          Attacker Demo
        </h2>
        <div style={{ fontSize: "0.8rem", color: "#9ca3af", marginBottom: "8px" }}>
          Paste an intercepted encrypted payload below and try decrypting it with
          the current device key. If this browser does not hold the intended
          recipient’s private key, decryption should fail.
        </div>

        <div style={styles.form}>
          <label style={styles.label}>
            Ciphertext
            <textarea
              style={{ ...styles.input, minHeight: "70px" }}
              value={attackerCiphertext}
              onChange={(e) => setAttackerCiphertext(e.target.value)}
              placeholder="Paste intercepted ciphertext here"
            />
          </label>

          <label style={styles.label}>
            Encrypted AES Key
            <textarea
              style={{ ...styles.input, minHeight: "70px" }}
              value={attackerEncryptedKey}
              onChange={(e) => setAttackerEncryptedKey(e.target.value)}
              placeholder="Paste intercepted encryptedKey here"
            />
          </label>

          <label style={styles.label}>
            IV
            <textarea
              style={{ ...styles.input, minHeight: "50px" }}
              value={attackerIv}
              onChange={(e) => setAttackerIv(e.target.value)}
              placeholder="Paste intercepted iv here"
            />
          </label>

          <button
            type="button"
            style={styles.primaryButton}
            onClick={handleAttackerDecrypt}
          >
            Attempt Decrypt With Current Device Key
          </button>

          {attackerResult && (
            <div style={styles.userBox}>
              <strong>Result:</strong>
              <div style={{ marginTop: "6px" }}>{attackerResult}</div>
            </div>
          )}
        </div>

        <div style={styles.messageBox}>{message}</div>

        {token && (
          <div style={styles.tokenBox}>
            <strong>JWT token (shortened):</strong>
            <div style={{ fontSize: "0.8rem", wordBreak: "break-all" }}>
              {token.slice(0, 40)}...
            </div>
          </div>
        )}

        {me && (
          <div style={styles.userBox}>
            <h3>Current user</h3>
            <p>
              <strong>ID:</strong> {me.id}
            </p>
            <p>
              <strong>Email:</strong> {me.email}
            </p>
            <p>
              <strong>Created:</strong>{" "}
              {new Date(me.createdAt).toLocaleString()}
            </p>
            <p>
              <strong>Has public key stored:</strong>{" "}
              {me.hasPublicKey ? "Yes" : "No"}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}



const styles = {
  container: {
    minHeight: "100vh",
    background: "#0f172a",
    color: "#e5e7eb",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    padding: "16px",
    fontFamily: "system-ui, -apple-system, BlinkMacSystemFont, sans-serif",
  },
  card: {
    background: "#020617",
    borderRadius: "16px",
    padding: "24px",
    maxWidth: "520px",
    width: "100%",
    boxShadow: "0 20px 40px rgba(0,0,0,0.5)",
    border: "1px solid #1f2937",
  },
  inputWrapper: {
    position: "relative",
    display: "flex",
    alignItems: "center",
  },
  eyeButton: {
    position: "absolute",
    right: "8px",
    padding: "4px 8px",
    borderRadius: "999px",
    border: "none",
    background: "transparent",
    color: "#9ca3af",
    cursor: "pointer",
    fontSize: "0.8rem",
  },
  tabRow: {
    display: "flex",
    gap: "8px",
    marginBottom: "16px",
  },
  tabButton: {
    flex: 1,
    background: "#020617",
    color: "#9ca3af",
    border: "1px solid #1f2937",
    padding: "8px",
    borderRadius: "999px",
    cursor: "pointer",
  },
  tabButtonActive: {
    background: "#2563eb",
    color: "#f9fafb",
    borderColor: "#2563eb",
  },
  form: {
    display: "flex",
    flexDirection: "column",
    gap: "12px",
  },
  label: {
    fontSize: "0.9rem",
    display: "flex",
    flexDirection: "column",
    gap: "4px",
  },
  input: {
    padding: "8px",
    borderRadius: "8px",
    border: "1px solid #374151",
    background: "#020617",
    color: "#e5e7eb",
  },
  primaryButton: {
    marginTop: "8px",
    padding: "10px",
    borderRadius: "999px",
    border: "none",
    background: "#22c55e",
    color: "#022c22",
    fontWeight: "600",
    cursor: "pointer",
  },
  secondaryButton: {
    padding: "8px",
    borderRadius: "999px",
    border: "1px solid #4b5563",
    background: "transparent",
    color: "#e5e7eb",
    cursor: "pointer",
    width: "100%",
  },
  messageBox: {
    marginTop: "12px",
    fontSize: "0.9rem",
    minHeight: "20px",
  },
  tokenBox: {
    marginTop: "12px",
    padding: "8px",
    borderRadius: "8px",
    background: "#020617",
    border: "1px solid #1f2937",
    fontSize: "0.8rem",
  },
  userBox: {
    marginTop: "12px",
    padding: "8px",
    borderRadius: "8px",
    background: "#020617",
    border: "1px solid #1f2937",
  },
  shareCard: {
    marginBottom: "8px",
    padding: "8px",
    borderRadius: "8px",
    background: "#020617",
    border: "1px solid #1f2937",
  },
};

export default App;