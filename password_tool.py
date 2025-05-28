#!/usr/bin/env python3
"""
Password Strength Checker + Hash Cracker Tool
Author: Your Name
GitHub: https://github.com/yourusername/password-tool
"""

import re
import hashlib
import itertools
import argparse
from collections import Counter
import os
import sys

class PasswordTool:
    def __init__(self):
        self.common_passwords = set()
        self.load_common_passwords(os.path.join(os.path.dirname(__file__), 'wordlists/common_passwords.txt')
        
        self.hash_functions = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
            'sha3_256': hashlib.sha3_256,
            'blake2s': hashlib.blake2s
        }
    
    def load_common_passwords(self, base_path, file_path):
        full_path = os.path.join(base_path, file_path)
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as file:
                self.common_passwords = set(line.strip() for line in file if line.strip())
        except FileNotFoundError:
            print(f"Warning: Common passwords file '{full_path}' not found")
            self.common_passwords = set()

    def check_strength(self, password):
        """Check password strength and return score and rating"""
        if not password:
            return 0, "Empty password"
            
        if password.lower() in self.common_passwords:
            return 0, "Password is too common"
            
        length = len(password)
        score = 0
        
        # Length score
        score += min(length, 20) * 4
        
        # Character variety
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
        
        variety_count = sum([has_lower, has_upper, has_digit, has_special])
        score += (variety_count - 1) * 10
        
        # Deductions
        if length < 8:
            score -= (8 - length) * 5
            
        # Repeated characters
        repeats = sum(count - 1 for count in Counter(password).values() if count > 1)
        score -= repeats * 2
        
        # Sequential characters
        sequential = self.check_sequential(password)
        score -= sequential * 3
        
        # Normalize score to 0-100 range
        score = max(0, min(100, score))
        
        # Strength rating
        if score < 40:
            rating = "Very Weak"
        elif score < 60:
            rating = "Weak"
        elif score < 80:
            rating = "Moderate"
        elif score < 90:
            rating = "Strong"
        else:
            rating = "Very Strong"
            
        return score, rating
    
    def check_sequential(self, password):
        """Check for sequential characters"""
        sequential = 0
        for i in range(len(password) - 2):
            a, b, c = ord(password[i]), ord(password[i+1]), ord(password[i+2])
            if (a + 1 == b and b + 1 == c) or (a - 1 == b and b - 1 == c):
                sequential += 1
        return sequential
    
    def identify_hash(self, hash_str):
        """Identify hash type based on length"""
        length = len(hash_str)
        
        hash_types = {
            32: 'md5',
            40: 'sha1',
            56: 'sha224',
            64: 'sha256',
            96: 'sha384',
            128: 'sha512',
            64: 'sha3_256',
            64: 'blake2s'
        }
        
        return hash_types.get(length, None)
    
    def dictionary_attack(self, hash_str, wordlist_path='wordlists/wordlist.txt'):
        """Perform dictionary attack on hash"""
        hash_type = self.identify_hash(hash_str)
        if not hash_type:
            print("Unknown hash type")
            return None
            
        hash_func = self.hash_functions.get(hash_type)
        if not hash_func:
            print(f"Unsupported hash type: {hash_type}")
            return None
            
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
                for line in file:
                    word = line.strip()
                    if not word:
                        continue
                    try:
                        if hash_func(word.encode()).hexdigest() == hash_str:
                            return word
                    except UnicodeEncodeError:
                        continue
        except FileNotFoundError:
            print(f"Wordlist file '{wordlist_path}' not found")
            return None
        except Exception as e:
            print(f"Error during cracking: {str(e)}")
            return None
        
        return None
    
    def brute_force_attack(self, hash_str, max_length=4, charset=None):
        """Perform brute force attack on hash"""
        hash_type = self.identify_hash(hash_str)
        if not hash_type:
            print("Unknown hash type")
            return None
            
        hash_func = self.hash_functions.get(hash_type)
        if not hash_func:
            print(f"Unsupported hash type: {hash_type}")
            return None
            
        charset = charset or 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()'
        
        print(f"Brute forcing with max length {max_length}...")
        for length in range(1, max_length + 1):
            for attempt in itertools.product(charset, repeat=length):
                attempt_str = ''.join(attempt)
                if hash_func(attempt_str.encode()).hexdigest() == hash_str:
                    return attempt_str
                    
        return None

def main():
    tool = PasswordTool()
    parser = argparse.ArgumentParser(
        description="Password Strength Checker + Hash Cracker Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s strength 'MyP@ssw0rd'
  %(prog)s crack 5f4dcc3b5aa765d61d8327deb882cf99
  %(prog)s crack 5f4dcc3b5aa765d61d8327deb882cf99 --method bruteforce --max-length 5
""")
    
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # Password strength checker subcommand
    strength_parser = subparsers.add_parser('strength', help='Check password strength')
    strength_parser.add_argument('password', help='Password to check')
    
    # Hash cracker subcommand
    crack_parser = subparsers.add_parser('crack', help='Crack a hash')
    crack_parser.add_argument('hash', help='Hash to crack')
    crack_parser.add_argument('--method', choices=['dictionary', 'bruteforce'], default='dictionary',
                            help='Cracking method to use (default: dictionary)')
    crack_parser.add_argument('--wordlist', default='wordlists/wordlist.txt',
                            help='Path to wordlist file (default: wordlists/wordlist.txt)')
    crack_parser.add_argument('--max-length', type=int, default=4,
                            help='Maximum length for brute force attack (default: 4)')
    crack_parser.add_argument('--charset', default=None,
                            help='Custom character set for brute force (default: alphanumeric + special)')
    
    args = parser.parse_args()
    
    if args.command == 'strength':
        score, rating = tool.check_strength(args.password)
        print(f"\nPassword Analysis:")
        print(f"  Password: {args.password}")
        print(f"  Strength: {rating} ({score}/100)")
        
    elif args.command == 'crack':
        print(f"\nAttempting to crack hash: {args.hash}")
        
        if args.method == 'dictionary':
            print(f"Using dictionary attack with: {args.wordlist}")
            result = tool.dictionary_attack(args.hash, args.wordlist)
        else:
            print(f"Using brute force attack (max length: {args.max_length})")
            result = tool.brute_force_attack(args.hash, args.max_length, args.charset)
            
        if result:
            print(f"\nSuccess! Cracked password: {result}")
        else:
            print("\nFailed to crack the hash")

if __name__ == "__main__":
    main()
