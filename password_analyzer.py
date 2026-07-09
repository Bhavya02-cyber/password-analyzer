import re
import hashlib
import json
import os
from datetime import datetime
from typing import List, Tuple, Dict
import secrets
import string

class PasswordStrengthAnalyzer:
    def __init__(self, db_file='password_history.json'):
        self.db_file = db_file
        self.common_passwords = self._load_common_passwords()
        self.password_history = self._load_password_history()
        
    def _load_common_passwords(self) -> set:
        """Load common weak passwords"""
        common = {
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
            'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
            'bailey', 'passw0rd', 'shadow', '123123', '654321',
            'superman', 'qazwsx', 'michael', 'football', 'password1',
            'admin', 'welcome', 'login', 'admin123', 'root'
        }
        return common
    
    def _load_password_history(self) -> List[Dict]:
        """Load password history from database"""
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []
    
    def _save_password_history(self):
        """Save password history to database"""
        with open(self.db_file, 'w') as f:
            json.dump(self.password_history, f, indent=2)
    
    def _hash_password(self, password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def check_length(self, password: str) -> Tuple[int, str]:
        """Check password length and return score"""
        length = len(password)
        if length < 6:
            return 0, "Too short (minimum 6 characters)"
        elif length < 8:
            return 1, "Weak length (recommended 8+ characters)"
        elif length < 12:
            return 2, "Moderate length (good)"
        elif length < 16:
            return 3, "Strong length (very good)"
        else:
            return 4, "Excellent length"
    
    def check_complexity(self, password: str) -> Tuple[int, List[str]]:
        """Check password complexity"""
        score = 0
        feedback = []
        
        # Check for lowercase letters
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
        
        # Check for uppercase letters
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
        
        # Check for digits
        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append("Add numbers")
        
        # Check for special characters
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
            score += 1
        else:
            feedback.append("Add special characters (!@#$%^&*)")
        
        # Check for variety (not too repetitive)
        unique_chars = len(set(password))
        if unique_chars < len(password) * 0.5:
            score -= 1
            feedback.append("Too many repeated characters")
        
        return score, feedback
    
    def check_patterns(self, password: str) -> Tuple[int, List[str]]:
        """Check for common patterns and weaknesses"""
        issues = []
        score = 0
        
        # Check for sequential characters
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
            issues.append("Contains sequential letters")
            score -= 1
        
        if re.search(r'(012|123|234|345|456|567|678|789)', password):
            issues.append("Contains sequential numbers")
            score -= 1
        
        # Check for keyboard patterns
        keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', '1qaz', '2wsx']
        for pattern in keyboard_patterns:
            if pattern in password.lower():
                issues.append(f"Contains keyboard pattern: {pattern}")
                score -= 1
                break
        
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):
            issues.append("Contains repeated characters (3+ times)")
            score -= 1
        
        # Check for common words
        if password.lower() in self.common_passwords:
            issues.append("This is a commonly used password!")
            score -= 3
        
        # Check for dates
        if re.search(r'(19|20)\d{2}', password):
            issues.append("Contains year pattern")
            score -= 1
        
        return score, issues
    
    def check_uniqueness(self, password: str) -> Tuple[bool, str]:
        """Check if password was used before"""
        password_hash = self._hash_password(password)
        
        for entry in self.password_history:
            if entry['hash'] == password_hash:
                days_ago = (datetime.now() - datetime.fromisoformat(entry['created'])).days
                return False, f"Password was used {days_ago} days ago"
        
        return True, "Password is unique"
    
    def calculate_entropy(self, password: str) -> float:
        """Calculate password entropy (bits)"""
        charset_size = 0
        
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
            charset_size += 32
        
        if charset_size == 0:
            return 0
        
        import math
        entropy = len(password) * math.log2(charset_size)
        return entropy
    
    def analyze_password(self, password: str, check_history: bool = True) -> Dict:
        """Perform complete password analysis"""
        # Length check
        length_score, length_feedback = self.check_length(password)
        
        # Complexity check
        complexity_score, complexity_feedback = self.check_complexity(password)
        
        # Pattern check
        pattern_score, pattern_issues = self.check_patterns(password)
        
        # Uniqueness check
        is_unique = True
        uniqueness_feedback = "History check disabled"
        if check_history:
            is_unique, uniqueness_feedback = self.check_uniqueness(password)
        
        # Calculate entropy
        entropy = self.calculate_entropy(password)
        
        # Calculate total score
        total_score = length_score + complexity_score + pattern_score
        max_score = 12  # 4 (length) + 4 (complexity) + 4 (patterns, no deductions)
        
        # Determine strength level
        if total_score <= 3:
            strength = "Very Weak"
            color = "🔴"
        elif total_score <= 5:
            strength = "Weak"
            color = "🟠"
        elif total_score <= 7:
            strength = "Moderate"
            color = "🟡"
        elif total_score <= 9:
            strength = "Strong"
            color = "🟢"
        else:
            strength = "Very Strong"
            color = "🟢"
        
        return {
            'strength': strength,
            'color': color,
            'score': total_score,
            'max_score': max_score,
            'percentage': int((total_score / max_score) * 100) if total_score > 0 else 0,
            'entropy': entropy,
            'length_score': length_score,
            'length_feedback': length_feedback,
            'complexity_score': complexity_score,
            'complexity_feedback': complexity_feedback,
            'pattern_score': pattern_score,
            'pattern_issues': pattern_issues,
            'is_unique': is_unique,
            'uniqueness_feedback': uniqueness_feedback
        }
    
    def generate_strong_password(self, length: int = 16, 
                                 include_symbols: bool = True,
                                 include_numbers: bool = True,
                                 include_uppercase: bool = True,
                                 include_lowercase: bool = True) -> str:
        """Generate a cryptographically strong password"""
        characters = ''
        
        if include_lowercase:
            characters += string.ascii_lowercase
        if include_uppercase:
            characters += string.ascii_uppercase
        if include_numbers:
            characters += string.digits
        if include_symbols:
            characters += string.punctuation
        
        if not characters:
            characters = string.ascii_letters + string.digits
        
        # Ensure at least one character from each selected category
        password = []
        if include_lowercase:
            password.append(secrets.choice(string.ascii_lowercase))
        if include_uppercase:
            password.append(secrets.choice(string.ascii_uppercase))
        if include_numbers:
            password.append(secrets.choice(string.digits))
        if include_symbols:
            password.append(secrets.choice(string.punctuation))
        
        # Fill the rest randomly
        for _ in range(length - len(password)):
            password.append(secrets.choice(characters))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    def suggest_improvements(self, password: str) -> List[str]:
        """Suggest improvements for the password"""
        suggestions = []
        analysis = self.analyze_password(password, check_history=False)
        
        # Length suggestions
        if analysis['length_score'] < 3:
            suggestions.append(f"Increase length to at least 12 characters (currently {len(password)})")
        
        # Complexity suggestions
        if analysis['complexity_feedback']:
            suggestions.extend(analysis['complexity_feedback'])
        
        # Pattern warnings
        if analysis['pattern_issues']:
            suggestions.append("Avoid common patterns and predictable sequences")
        
        # General suggestions
        if not suggestions:
            suggestions.append("Your password is strong! Consider making it even longer for better security.")
        else:
            suggestions.append("Use a password manager to generate and store complex passwords")
        
        return suggestions
    
    def save_password(self, password: str, username: str = "user"):
        """Save password hash to history"""
        password_hash = self._hash_password(password)
        
        entry = {
            'hash': password_hash,
            'username': username,
            'created': datetime.now().isoformat(),
            'length': len(password)
        }
        
        self.password_history.append(entry)
        self._save_password_history()
    
    def display_analysis(self, password: str, check_history: bool = True):
        """Display formatted password analysis"""
        analysis = self.analyze_password(password, check_history)
        
        print("\n" + "="*60)
        print(f"PASSWORD STRENGTH ANALYSIS {analysis['color']}")
        print("="*60)
        
        # Overall strength
        print(f"\n🔐 Overall Strength: {analysis['strength']}")
        print(f"📊 Score: {analysis['score']}/{analysis['max_score']} ({analysis['percentage']}%)")
        
        # Progress bar
        bar_length = 30
        filled = int((analysis['percentage'] / 100) * bar_length)
        bar = "█" * filled + "░" * (bar_length - filled)
        print(f"   [{bar}] {analysis['percentage']}%")
        
        # Entropy
        print(f"\n🔢 Password Entropy: {analysis['entropy']:.2f} bits")
        if analysis['entropy'] < 28:
            print("   ⚠️  Very weak - can be cracked quickly")
        elif analysis['entropy'] < 36:
            print("   ⚠️  Weak - vulnerable to attacks")
        elif analysis['entropy'] < 60:
            print("   ✓  Moderate - reasonably secure")
        elif analysis['entropy'] < 80:
            print("   ✓✓ Strong - very secure")
        else:
            print("   ✓✓✓ Excellent - extremely secure")
        
        # Detailed feedback
        print(f"\n📏 Length: {analysis['length_feedback']}")
        
        print(f"\n🔧 Complexity (Score: {analysis['complexity_score']}/4):")
        if analysis['complexity_feedback']:
            for feedback in analysis['complexity_feedback']:
                print(f"   ❌ {feedback}")
        else:
            print("   ✓ All character types included")
        
        if analysis['pattern_issues']:
            print(f"\n⚠️  Pattern Issues (Score: {analysis['pattern_score']}):")
            for issue in analysis['pattern_issues']:
                print(f"   ❌ {issue}")
        
        if check_history:
            print(f"\n🔄 Uniqueness: {analysis['uniqueness_feedback']}")
            if not analysis['is_unique']:
                print("   ⚠️  Consider using a new password")
        
        # Suggestions
        print("\n💡 Suggestions for Improvement:")
        suggestions = self.suggest_improvements(password)
        for i, suggestion in enumerate(suggestions, 1):
            print(f"   {i}. {suggestion}")
        
        print("\n" + "="*60)


def interactive_mode():
    """Interactive password analyzer"""
    analyzer = PasswordStrengthAnalyzer()
    
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║        PASSWORD STRENGTH ANALYZER                        ║
    ║           Secure Your Digital Life                       ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    while True:
        print("\n📋 MENU:")
        print("1. Analyze a password")
        print("2. Generate a strong password")
        print("3. View password history")
        print("4. Clear password history")
        print("5. Batch test passwords")
        print("6. Exit")
        
        choice = input("\nSelect an option (1-6): ").strip()
        
        if choice == '1':
            password = input("\n🔑 Enter password to analyze: ")
            if not password:
                print("❌ Password cannot be empty!")
                continue
            
            check_history = input("Check against password history? (y/n): ").lower() == 'y'
            analyzer.display_analysis(password, check_history)
            
            save = input("\n💾 Save this password to history? (y/n): ").lower()
            if save == 'y':
                username = input("Enter username (optional): ").strip() or "user"
                analyzer.save_password(password, username)
                print("✓ Password saved to history")
        
        elif choice == '2':
            print("\n🎲 Password Generator Options:")
            try:
                length = int(input("Length (8-128, default 16): ") or "16")
                length = max(8, min(128, length))
            except:
                length = 16
            
            include_symbols = input("Include symbols? (Y/n): ").lower() != 'n'
            include_numbers = input("Include numbers? (Y/n): ").lower() != 'n'
            include_uppercase = input("Include uppercase? (Y/n): ").lower() != 'n'
            include_lowercase = input("Include lowercase? (Y/n): ").lower() != 'n'
            
            count = int(input("How many passwords to generate? (1-10): ") or "1")
            count = max(1, min(10, count))
            
            print(f"\n🔐 Generated Password{'s' if count > 1 else ''}:")
            for i in range(count):
                password = analyzer.generate_strong_password(
                    length, include_symbols, include_numbers,
                    include_uppercase, include_lowercase
                )
                print(f"{i+1}. {password}")
                
                # Quick analysis of generated password
                analysis = analyzer.analyze_password(password, check_history=False)
                print(f"   Strength: {analysis['strength']} {analysis['color']} (Entropy: {analysis['entropy']:.1f} bits)")
        
        elif choice == '3':
            if not analyzer.password_history:
                print("\n📭 No passwords in history")
            else:
                print(f"\n📜 Password History ({len(analyzer.password_history)} entries):")
                print("-" * 60)
                for i, entry in enumerate(analyzer.password_history[-10:], 1):  # Show last 10
                    created = datetime.fromisoformat(entry['created'])
                    print(f"{i}. User: {entry['username']}")
                    print(f"   Length: {entry['length']} | Created: {created.strftime('%Y-%m-%d %H:%M')}")
                    print(f"   Hash: {entry['hash'][:16]}...")
                    print()
        
        elif choice == '4':
            confirm = input("\n⚠️  Clear all password history? (yes/no): ")
            if confirm.lower() == 'yes':
                analyzer.password_history = []
                analyzer._save_password_history()
                print("✓ Password history cleared")
        
        elif choice == '5':
            print("\n📝 Batch Password Testing")
            print("Enter passwords (one per line, empty line to finish):")
            passwords = []
            while True:
                pwd = input()
                if not pwd:
                    break
                passwords.append(pwd)
            
            if passwords:
                print(f"\n📊 Testing {len(passwords)} passwords...")
                print("\n" + "="*60)
                for i, pwd in enumerate(passwords, 1):
                    analysis = analyzer.analyze_password(pwd, check_history=False)
                    print(f"{i}. {pwd[:20]}{'...' if len(pwd) > 20 else ''}")
                    print(f"   {analysis['color']} {analysis['strength']} - {analysis['percentage']}% - {analysis['entropy']:.1f} bits")
                print("="*60)
        
        elif choice == '6':
            print("\n👋 Thank you for using Password Strength Analyzer!")
            print("Stay secure! 🔐")
            break
        
        else:
            print("❌ Invalid option. Please try again.")


if __name__ == "__main__":
    # You can run in interactive mode
    interactive_mode()
    
    # Or use the analyzer programmatically:
    """
    analyzer = PasswordStrengthAnalyzer()
    
    # Test some passwords
    test_passwords = [
        "password123",
        "P@ssw0rd",
        "MyS3cur3P@ssw0rd!2024",
        "Tr0ub4dor&3",
        "correct horse battery staple"
    ]
    
    for pwd in test_passwords:
        print(f"\nTesting: {pwd}")
        analyzer.display_analysis(pwd, check_history=False)
    """