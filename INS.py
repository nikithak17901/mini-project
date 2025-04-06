import hashlib
import random
from Crypto.Util.number import getPrime, isPrime, inverse
import json
from datetime import datetime, timedelta
import os

# ANSI color codes for better menu visuals
BLUE = '\033[94m'
CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
MAGENTA = '\033[95m'
RESET = '\033[0m'
BOLD = '\033[1m'

class DSS:
    def __init__(self, L=2048, N=256):
        self.L = L
        self.N = N
        self.generate_parameters()
    
    def generate_parameters(self):
        self.q = getPrime(self.N)
        while True:
            k = random.getrandbits(self.L - self.N)
            p_candidate = k * self.q + 1
            if isPrime(p_candidate) and p_candidate.bit_length() == self.L:
                self.p = p_candidate
                break
        
        h = 2
        while True:
            g = pow(h, (self.p - 1) // self.q, self.p)
            if g != 1:
                self.g = g
                break
            h += 1
    
    def generate_keys(self):
        self.x = random.randint(1, self.q - 1)
        self.y = pow(self.g, self.x, self.p)
        return (self.x, self.y)
    
    def sign(self, message, x=None):
        if x is None:
            x = self.x
        
        H = int.from_bytes(hashlib.sha256(message).digest(), byteorder='big')
        H = H % self.q
        if H == 0:
            H = 1
        
        while True:
            k = random.randint(1, self.q - 1)
            r = pow(self.g, k, self.p) % self.q
            if r == 0:
                continue
            
            try:
                k_inv = inverse(k, self.q)
            except ValueError:
                continue
            
            s = (k_inv * (H + x * r)) % self.q
            if s == 0:
                continue
            
            return (r, s)
    
    def verify(self, message, signature, y=None):
        if y is None:
            y = self.y
        
        r, s = signature
        
        if not (0 < r < self.q and 0 < s < self.q):
            return False
        
        H = int.from_bytes(hashlib.sha256(message).digest(), byteorder='big')
        H = H % self.q
        if H == 0:
            H = 1
        
        try:
            w = inverse(s, self.q)
        except ValueError:
            return False
        
        u1 = (H * w) % self.q
        u2 = (r * w) % self.q
        v = (pow(self.g, u1, self.p) * pow(y, u2, self.p)) % self.p % self.q
        
        return v == r

class CertificateAuthority:
    def __init__(self):
        self.dss = DSS()
        self.ca_private, self.ca_public = self.dss.generate_keys()
        self.certificates = {}
        self.user_data = {}

    def generate_user_certificate(self, user_id):
        user_dss = DSS()
        user_private, user_public = user_dss.generate_keys()
        
        cert = {
            'version': '1.0',
            'serial': random.getrandbits(128),
            'issuer': 'CA',
            'subject': user_id,
            'valid_from': datetime.now().strftime('%Y-%m-%d'),
            'valid_to': (datetime.now() + timedelta(days=365)).strftime('%Y-%m-%d'),
            'public_key': user_public,
        }
        
        cert_bytes = json.dumps(cert, sort_keys=True, separators=(',', ':')).encode()
        signature = self.dss.sign(cert_bytes, self.ca_private)
        cert['signature'] = signature
        
        self.certificates[user_id] = cert
        self.user_data[user_id] = {
            'dss': user_dss,
            'private_key': user_private,
            'public_key': user_public
        }
        return cert

    def verify_certificate(self, cert):
        if not cert or 'signature' not in cert:
            return False
        
        cert_copy = cert.copy()
        signature = cert_copy.pop('signature')
        cert_bytes = json.dumps(cert_copy, sort_keys=True, separators=(',', ':')).encode()
        return self.dss.verify(cert_bytes, signature, self.ca_public)

def sign_and_verify(user_dss, private_key, public_key):
    message = input("\n📝 Enter message to sign: ").encode()
    signature = user_dss.sign(message, private_key)
    print(f"\n🔏 Signature (r, s): {signature}")
    
    is_valid = user_dss.verify(message, signature, public_key)
    print(f"✅ Verification: {GREEN}SUCCESS{RESET}" if is_valid else f"{RED}❌ FAILED{RESET}")
    return is_valid

def simulate_attack(dss):
    print(f"\n{YELLOW}=== Tamper Detection Test ==={RESET}")
    original = b"Valid message"
    tampered = b"Tampered message"
    
    sig = dss.sign(original)
    print(f"🆗 Original signature: {sig}")
    print(f"✔️  Verify original: {dss.verify(original, sig)} (Expected: True)")
    print(f"❗ Verify tampered: {dss.verify(tampered, sig)} (Expected: False)")

def display_menu():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{BOLD}{BLUE}🔐 Digital Signature Scheme System{RESET}\n")
    print(f"{YELLOW}📌 Select an Option:{RESET}")
    print(f"{CYAN} 1. 👤 Create User")
    print(f" 2. ✍️  Sign and Verify Message")
    print(f" 3. ⚠️  Simulate Message Tampering Attack")
    print(f" 4. ❌ Exit{RESET}")

def main():
    ca = CertificateAuthority()
    current_user = None
    
    while True:
        display_menu()
        choice = input(f"\n🧭 Enter your choice (1-4): ").strip()
        
        if choice == "1":
            user_id = input("\n🆔 Enter user ID: ").strip()
            if user_id in ca.user_data:
                print(f"{RED}⚠️ User already exists!{RESET}")
                input("\nPress Enter to continue...")
                continue
                
            cert = ca.generate_user_certificate(user_id)
            current_user = user_id
            print(f"\n✅ Created user '{user_id}'")
            print(f"🔑 Public Key: {ca.user_data[user_id]['public_key']}")
            input("\nPress Enter to continue...")
            
        elif choice == "2":
            if not current_user:
                print(f"{RED}⚠️ Please create a user first!{RESET}")
                input("\nPress Enter to continue...")
                continue
                
            user = ca.user_data[current_user]
            sign_and_verify(user['dss'], user['private_key'], user['public_key'])
            input("\nPress Enter to continue...")
            
        elif choice == "3":
            simulate_attack(ca.dss)
            input("\nPress Enter to continue...")
            
        elif choice == "4":
            print(f"\n{MAGENTA}👋 Goodbye!{RESET}")
            break
            
        else:
            print(f"{RED}❌ Invalid choice! Please try again.{RESET}")
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
