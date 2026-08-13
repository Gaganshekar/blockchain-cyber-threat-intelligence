# 🔐 Blockchain-Based Cyber Threat Intelligence Sharing Platform

A web-based Cyber Threat Intelligence (CTI) platform developed using **Python**, **Flask**, **SQLite**, and a lightweight **Blockchain**. The application enables users to submit, check, and securely store cyber threat information in an immutable blockchain ledger.

---

## 📖 Project Overview

Cyber attacks such as phishing, ransomware, malware, botnets, and data breaches are increasing rapidly. Organizations need a secure way to share cyber threat intelligence without the risk of data tampering.

This project provides a lightweight blockchain-based solution that allows users to:

- Submit cyber threat reports
- Check indicators such as URLs, IP addresses, domains, emails, and file hashes
- Store reports securely in a blockchain
- View all blockchain records
- Verify blockchain integrity

---

## 🎯 Objectives

- Secure cyber threat information
- Prevent data tampering
- Share threat intelligence
- Demonstrate blockchain concepts
- Build a responsive cyber security dashboard

---

## 🛠 Technologies Used

| Technology | Purpose |
|------------|---------|
| Python | Backend Programming |
| Flask | Web Framework |
| SQLite | Database |
| HTML5 | Frontend |
| CSS3 | Styling |
| JavaScript | Client-side Interaction |
| SHA-256 | Blockchain Hashing |

---

## 📂 Project Structure

```
Blockchain-CTI/
│
├── app.py
├── blockchain.py
├── database.py
├── threat_checker.py
├── threats.db
├── requirements.txt
├── README.md
│
├── templates/
│   ├── index.html
│   ├── checker.html
│   ├── submit.html
│   ├── blockchain.html
│   └── about.html
│
└── static/
    ├── css/
    │   └── style.css
    └── js/
        └── script.js
```

---

## ✨ Features

- Responsive cyber security website
- Submit cyber threats
- Threat checker
- Blockchain ledger
- SHA-256 hashing
- SQLite database
- Modern UI
- Flask backend
- Blockchain validation
- Searchable threat indicators

---

## 📊 Supported Threat Types

- Malware
- Phishing
- Ransomware
- Trojan
- Spyware
- Botnet
- DDoS
- Zero-Day
- Data Breach

---

## 🔗 Blockchain Workflow

```
User
   │
   ▼
Submit Threat
   │
   ▼
SQLite Database
   │
   ▼
Create Blockchain Block
   │
   ▼
Generate SHA-256 Hash
   │
   ▼
Blockchain Ledger
```

---

## ⚙ Installation

### Step 1

Clone the repository

```bash
git clone https://github.com/yourusername/Blockchain-CTI.git
```

or download the ZIP file.

---

### Step 2

Open the project folder.

---

### Step 3

Install dependencies.

```bash
pip install -r requirements.txt
```

---

### Step 4

Run the application.

```bash
python app.py
```

---

### Step 5

Open your browser.

```
http://127.0.0.1:5000
```

---

## 🌐 Website Pages

### Home
Displays project overview, latest cyber threats, statistics, and navigation.

### Threat Checker
Checks:

- URL
- Domain
- IP Address
- Email Address
- MD5 Hash
- SHA-256 Hash

---

### Submit Threat

Allows users to report cyber threats.

Information collected:

- Threat Title
- Category
- Severity
- Indicator
- Description
- Reporter Name

---

### Blockchain Ledger

Displays:

- Block Number
- Timestamp
- Threat Title
- Category
- Severity
- Previous Hash
- Current Hash

---

### About

Displays:

- Project Overview
- Objectives
- Workflow
- Technologies
- Features

---

## 🗄 Database Schema

Table Name

```
threats
```

Columns

```
id
title
category
severity
indicator
description
reporter
created_at
```

---

## 🔒 Security Features

- SHA-256 hashing
- Immutable blockchain
- Input validation
- Threat verification
- Blockchain integrity checking

---

## 🚀 Future Enhancements

- User Authentication
- Admin Dashboard
- VirusTotal API Integration
- AbuseIPDB Integration
- Real-time Threat Feed
- Email Notifications
- PDF Report Export
- Charts and Analytics
- REST API
- Multi-user Support

---

## 📸 Screenshots

Add screenshots of:

- Home Page
- Threat Checker
- Submit Threat
- Blockchain Ledger
- About Page

---

## 👨‍💻 Developed By

**Name:** Gaganshekar C

**Course:** Master of Computer Applications (MCA)

**Academic Year:** 2024

---

## 📄 License

This project is developed for educational and academic purposes.
