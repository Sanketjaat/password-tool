# 🔐 Password Strength Checker & Hash Cracker Tool

![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Last Commit](https://img.shields.io/github/last-commit/Sanketjaat/password-tool)
![Repo Size](https://img.shields.io/github/repo-size/Sanketjaat/password-tool)

A powerful cybersecurity tool that combines password strength analysis and hash cracking capabilities in one package.

## ✨ Features

- **Password Strength Analysis**
  - Detailed strength scoring (0-100)
  - Common password detection
  - Character variety evaluation
  - Sequential/repeated character checks
  
- **Hash Cracking**
  - Supports MD5, SHA1, SHA256, SHA512, SHA3, BLAKE2
  - Dictionary attacks with custom wordlists
  - Configurable brute force attacks
  - Automatic hash type detection

- **Additional Features**
  - Clean command-line interface
  - Customizable attack parameters
  - Wordlist management
  - Progress indicators

## 🛠 Installation

### Prerequisites
- Python 3.6+
- pip package manager

### Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/password-tool.git
cd password-tool

# The tool requires Python 3.6+ (no additional packages needed)
python --version  # Verify version

# Make the script executable
chmod +x password_tool.py

# Download sample wordlists (optional)
./download_wordlists.sh

```
Basic Commands
```bash

# Check password strength
python password_tool.py strength 'YourP@ssw0rd!'

# Crack hash using dictionary attack
python password_tool.py crack 5f4dcc3b5aa765d61d8327deb882cf99

# Crack hash using brute force
python password_tool.py crack 5f4dcc3b5aa765d61d8327deb882cf99 --method bruteforce --max-length 5
```
Advanced Options

```bash
# Use custom wordlist
python password_tool.py crack [HASH] --wordlist path/to/custom_wordlist.txt

# Set custom character set for brute force
python password_tool.py crack [HASH] --method bruteforce --charset "abcdef123"

# Increase max length for brute force
python password_tool.py crack [HASH] --method bruteforce --max-length 8
```
🌟 Example Output

Password Strength Check

```bash
Password Analysis:
  Password: P@ssw0rd2023!
  Strength: Very Strong (94/100)
```
Hash Cracking
```bash
Attempting to crack hash: 5f4dcc3b5aa765d61d8327deb882cf99
Using dictionary attack with: wordlists/wordlist.txt
```
Success! Cracked password: password
