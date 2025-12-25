
# Cyberthon – File & APK Security Analyzer

A lightweight **static security analysis tool** for files and Android APKs.
Works locally. No execution. No installation of APKs.

---

## What This Project Does

* Scans files for security risks
* Detects:

  * Malware-like patterns
  * Keylogger indicators
  * Extension spoofing
  * Spyware-style behavior
* Special handling for **Android APKs**

  * Analyzes permissions
  * Flags dangerous permission combinations
  * Explains *why* an APK is risky

---

## Project Structure

```
cyberthon/
│
├── backend/
│   ├── server.py          # Flask backend for APK analysis
│   ├── apk_analyzer.py    # APK permission logic
│   └── requirements.txt
│
├── index.html             # Scanner UI
├── results.html           # Results page
├── main.js                # Core analysis logic
└── README.md
```

---

## Setup & Run (Windows / Linux / macOS)

### 1️⃣ Clone the repo

```bash
git clone https://github.com/shlokkokk/cyberthon.git
cd cyberthon
```

---

### 2️⃣ Backend setup (APK analysis)

#### Windows

```powershell
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python server.py
```

#### Linux / macOS

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python server.py
```

Backend runs on:

```
http://localhost:5000
```


