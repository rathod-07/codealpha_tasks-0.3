# 🔒 Secure Code Review & Authentication (CodeAlpha_Task-3)

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Domain](https://img.shields.io/badge/Domain-Cyber%20Security-red.svg)
![Internship](https://img.shields.io/badge/CodeAlpha-Cyber%20Security%20Internship-orange.svg)
![Task](https://img.shields.io/badge/Task-Task%203-brightgreen.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

---

## 📌 Executive Summary

This repository contains *Task 3* for the *CodeAlpha Cyber Security Internship. It features a comprehensive **Secure Code Review* for a Python User Authentication module, analyzing a vulnerable implementation (vulnerable_app.py) side-by-side with its hardened, secure counterpart (secure_app.py).

The remediation addresses critical security flaws, including *SQL Injection* and *Hardcoded Credentials*, replacing them with secure parameterized queries, environment-based configuration, and salted PBKDF2 password hashing.

> ⚠️ *Training Warning:* vulnerable_app.py is intentionally unsafe and uses placeholder credentials for educational purposes only. Do *not* deploy it in a production environment.

---

## ⚠️ Vulnerability Analysis

| Finding | OWASP Top 10 (2021) | CWE | Severity | Risk & Impact |
|---|---|---|---|---|
| *SQL Injection* (f-strings) | [A03: Injection](https://owasp.org/Top10/A03_2021-Injection/) | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | *High / Critical* | Untrusted user input alters SQL query logic, allowing attackers to bypass authentication or access database contents. |
| *Hardcoded Credentials* | [A07: Identification Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | *High* | Embedded database secrets in source code expose direct database access to anyone with source control access. |

---

## 🛡️ Remediation Summary

1. *SQL Injection Fix:* Replaced string interpolation with parameterized queries (WHERE username = %s, (username,)) using psycopg3.
2. *Credential Protection:* Removed hardcoded credentials and migrated config retrieval to system environment variables (os.getenv).
3. *Password Security:* Replaced plaintext password comparisons with salted PBKDF2-HMAC-SHA256 hashing and timing-attack safe comparison (hmac.compare_digest).
4. *Least Privilege:* Enforced access control principles for application database accounts.

---

## 📁 Repository Structure

- 📄 vulnerable_app.py – Demonstration of insecure authentication patterns (SQLi & hardcoded secrets).
- 🛡️ secure_app.py – Remediated, production-ready secure authentication code.
- 📑 README.md – Security documentation and vulnerability analysis.

---

## 🚀 How to Setup & Run

### Prerequisites

- Python 3.8+
- PostgreSQL Database

### Installation & Execution

```bash
# 1. Install Psycopg 3
pip install "psycopg[binary]"

# 2. Set Required Environment Variables
export DB_HOST="localhost"
export DB_NAME="secure_db"
export DB_USER="app_user"
export DB_PASSWORD="your_secure_password"

# 3. Run Secure Application
python secure_app.py# codealpha_tasks-0.3
