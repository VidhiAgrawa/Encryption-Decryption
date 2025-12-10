# 🔐 Encryption–Decryption Application

A simple and efficient Node.js-based application for encrypting and decrypting text. This project demonstrates core cryptographic operations with a clean file structure and an easy-to-use interface.

---

## 📌 Features

- Encrypt text securely  
- Decrypt encrypted text  
- Clean and modular cryptographic logic (`cryptoLogic.js`)  
- Simple frontend interface using views  
- Node.js server setup for handling requests  
- Easy to extend and customize  

---

## 📁 Project Structure

Encryption-Decryption/
│
├── models/ # (Optional) models, if extended later
├── views/ # UI templates (EJS/HTML)
├── cryptoLogic.js # Core encryption & decryption functions
├── server.js # App entry point
├── .env # Environment variables (if required)
├── package.json # Metadata & dependencies
└── README.md # Documentation


---

## 🚀 Getting Started

### **Prerequisites**
- Node.js (v14 or above)
- npm or yarn package manager

---

### **Installation**
git clone https://github.com/VidhiAgrawa/Encryption-Decryption.git
cd Encryption-Decryption
npm install

###Run the Application
npm start

###🧠 How It Works

The application separates logic into clear modules:

cryptoLogic.js → Handles all encryption and decryption functions

server.js → Runs the Node.js server and connects routes

views/ → Frontend pages for user input & result display

This structure makes it easy to expand with more algorithms, APIs, or UI upgrades.


###👩‍💻 Author

Vidhi Agrawal
GitHub: VidhiAgrawa
