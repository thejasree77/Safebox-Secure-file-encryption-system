SafeBox - Secure File Encryption and Sharing System
SafeBox is a web application that helps users securely encrypt, store and share files. It is mainly focused on protecting files and giving users more control over how their files are shared.
Features
- File encryption and decryption
- Secure file sharing
- Key management
- Self-destructing share links
- Tamper detection
- Security event monitoring
- Security recommendations
- User login and registration
- File management
Technologies Used
- Python
- Flask
- HTML
- CSS
- JavaScript
- SQLite
- Cryptography
How to Run
Clone the repository:
git clone https://github.com/thejasree77/Safebox-Secure-file-encryption-system.git

Go to the project folder:
cd Safebox-Secure-file-encryption-system

Install the required packages:
pip install -r requirements.txt

Run the application:
python app.py

Then open:
http://127.0.0.1:5000

Project Structure
app.py
crypto_utils.py
requirements.txt
static/
templates/
.gitignore

Security
Sensitive files and keys are not uploaded to GitHub. Files such as secret.key, database.db, and storage folders are excluded using .gitignore.
Disclaimer
This project is currently developed as an educational project and demonstration. It should not be used to store highly sensitive or confidential files.
