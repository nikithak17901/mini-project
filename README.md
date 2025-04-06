Digital-Signature-Scheme

A secure, web-based application that implements the Digital Signature Standard (DSS) using Elliptic Curve Cryptography (ECDSA). This project demonstrates a real-world cryptographic system for message signing, verification, and key management, tailored with a modern and interactive user interface.

📌 Features

Key Pair Generation (ECDSA with SECP256R1 curve)
Digital Signing of user-input messages
Signature Verification
Signing History with timestamps
User Authentication (Sign up & login)
JSON-based lightweight storage (no DB needed)
Glassmorphism + Cyberpunk themed UI


How to run 
✅ 1. Make Sure You Have Python Installed
Ensure Python 3 is installed.

Check by running
python --version
If not installed, download from: https://www.python.org/downloads/


✅ 2. Install Required Libraries
This script uses pycryptodome. Install it using:

pip install pycryptodome

✅ 3. Save the Script
Copy your code into a file, e.g., dss_system.py

✅ 4. Run the Script
Open a terminal/command prompt, navigate to the script location, then run:

bash
Copy
Edit
python dss_system.py
or
python3 dss_system.py


🧪 Example Run
bash
Copy
Edit
$ python dss_system.py
🔐 Digital Signature Scheme System

📌 Select an Option:
 1. 👤 Create User
 2. ✍️  Sign and Verify Message
 3. ⚠️  Simulate Message Tampering Attack
 4. ❌ Exit

🧭 Enter your choice (1-4): 1
🆔 Enter user ID: alice
✅ Created user 'alice'
🔑 Public Key: 123456789...

Press Enter to continue...
