# Secure Password Manager

Secure Password Manager is a small Python/Flask web application that combines a password strength checker with an encrypted password vault.

## Features

- Password strength analysis using:
  - length checks
  - character variety checks
  - entropy estimation
  - estimated crack time
  - local common-password wordlist
  - optional Have I Been Pwned breach check
- Encrypted password vault using Fernet symmetric encryption
- SQLite database for local storage
- Flask web interface with multiple pages
- Blocks weak passwords from being saved

## Why I built this

I built this project to  apply different concepts I learnt in competetitons and in class such as pasword hashing and cryptography. I wanted to create a practical tool that can show how password security works in real life. 

## Project Structure

```text
secure-password-toolkit/
├── app.py
├── checker.py
├── crypto_utils.py
├── database.py
├── data/
│   └── words.txt
├── static/
│   └── style.css
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── add.html
│   └── vault.html
├── requirements.txt
├── .gitignore
└── README.md
```

## Setup

Create and activate a virtual environment:

```bash
python -m venv venv
```

On Windows:

```bash
venv\Scripts\activate
```

On macOS/Linux:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the app:

```bash
python app.py
```

Open in your browser:

```text
http://127.0.0.1:5000
```

## Security Notes

The Have I Been Pwned check uses the k-anonymity model, meaning only the first five characters of the SHA-1 hash are sent to the API, not the full password.
