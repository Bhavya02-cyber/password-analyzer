# 🔐 Password Strength Analyzer

A Python tool that evaluates password strength, generates secure passwords, and prevents password reuse.

## Features

- ✅ Password strength analysis (length, complexity, patterns)
- ✅ Cryptographically secure password generation
- ✅ Password history tracking (prevents reuse)
- ✅ Entropy calculation
- ✅ Batch testing mode
- ✅ Interactive CLI interface

## Quick Start

```bash
# Clone repository
git clone https://github.com/yourusername/password-analyzer.git
cd password-analyzer

# Run (no dependencies needed!)
python password_analyzer.py
Usage
Interactive Mode
Bash

python password_analyzer.py
Programmatic Use
Python

from password_analyzer import PasswordStrengthAnalyzer

analyzer = PasswordStrengthAnalyzer()

# Analyze password
result = analyzer.analyze_password("MyP@ssw0rd123")
print(f"Strength: {result['strength']}")

# Generate strong password
password = analyzer.generate_strong_password(length=16)
Scoring System
Score	Strength	Security Level
0-3	🔴 Very Weak	Easily cracked
4-5	🟠 Weak	Vulnerable
6-7	🟡 Moderate	Reasonably secure
8-9	🟢 Strong	Very secure
10-12	🟢 Very Strong	Excellent
What It Checks
Length: Minimum 6 chars, recommends 12+
Complexity: Uppercase, lowercase, numbers, symbols
Patterns: Sequential chars, keyboard patterns, repetition
Common passwords: Checks against weak password database
Entropy: Measures password randomness in bits
```

### Security Features
🔒 SHA-256 hashing (no plaintext storage)
🔒 Cryptographically secure RNG (secrets module)
🔒 Local processing (passwords never leave your computer)
🔒 Pattern detection (15+ weakness checks)

### Example Output

============================================================
PASSWORD STRENGTH ANALYSIS 🟢
============================================================

🔐 Overall Strength: Very Strong
📊 Score: 10/12 (83%)
   [████████████████████████░░░░░░] 83%

🔢 Password Entropy: 95.27 bits
   ✓✓✓ Excellent - extremely secure

💡 Suggestions:
   1. Your password is strong!
   2. Use a password manager
