# Secure Chat Project

## Current Status

The project setup is working.
Client and server connection is working.
Handshake flow is added and running.

---

## Work Completed by Sri

### Backend / Security Part

### ✔ Connection Setup

* Client connects to server
* Server accepts connection

### ✔ Diffie-Hellman Initialization

* Added loading of crypto parameters from `params`
* Added secure handshake start flow

### ✔ Temporary Key Generation

* Client generates temporary DH public/private key
* Server generates temporary DH public/private key

### ✔ Shared Secret Flow

* Added shared secret derivation stage for both sides

### ✔ Debug Verification

* Added terminal logs to verify all handshake steps are running properly

### ✔ GitHub Updates

* All current backend changes pushed to GitHub

---

## What Is Working Now

Run:

```bash id="z0s80f"
./chat -l
./chat -c localhost
```

Current result:

* Chat window opens
* Client and server connect
* Handshake starts
* Keys generate successfully
* Shared secret flow starts

---

## Remaining Work (Next Part To Complete)

### Frontend / Messaging Part

### 1. Send Messages Properly

Connect send button with actual message transfer.

### 2. Encrypt Outgoing Messages

Use shared secret key to encrypt messages before sending.

### 3. Decrypt Incoming Messages

Decrypt received messages and display in chat window.

### 4. Improve UI

Fix missing `colors.css` file and improve interface.

### 5. Add Secure Status Message

Examples:

* Connected Securely
* Encrypted Session Active

### 6. Final Testing

Check:

* Messages send correctly
* Messages receive correctly
* Encryption works
* No crashes
* UI works cleanly

---

## Final Goal

Complete secure chat application with:

* GUI chat window
* Secure key exchange
* Encrypted messaging
* Working send/receive communication

---

## Note

I (Sri) have completed the backend secure handshake and connection part.
Next step is mainly message encryption, decryption, and UI completion.
