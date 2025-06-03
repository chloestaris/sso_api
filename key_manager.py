from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import os
import json
from datetime import datetime, timedelta

class KeyManager:
    def __init__(self, keys_dir='instance/keys'):
        self.keys_dir = keys_dir
        self.private_key = None
        self.public_key = None
        self.kid = None
        # Create keys directory with proper permissions
        os.makedirs(self.keys_dir, mode=0o700, exist_ok=True)

    def generate_key_pair(self):
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Get public key
        public_key = private_key.public_key()

        # Generate key ID (kid)
        kid = datetime.utcnow().strftime('%Y%m%d-%H%M%S')

        # Ensure directory exists with proper permissions
        os.makedirs(self.keys_dir, mode=0o700, exist_ok=True)

        private_key_path = os.path.join(self.keys_dir, f'private-{kid}.pem')
        public_key_path = os.path.join(self.keys_dir, f'public-{kid}.pem')

        # Save private key with restricted permissions
        with open(private_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        os.chmod(private_key_path, 0o600)

        # Save public key
        with open(public_key_path, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        os.chmod(public_key_path, 0o644)

        self.private_key = private_key
        self.public_key = public_key
        self.kid = kid

        return kid

    def load_keys(self, kid=None):
        if not os.path.exists(self.keys_dir):
            return self.generate_key_pair()

        if kid is None:
            # Load the most recent key
            private_keys = [f for f in os.listdir(self.keys_dir) if f.startswith('private-')]
            if not private_keys:
                return self.generate_key_pair()
            kid = max(private_keys).split('-')[1].split('.')[0]

        private_key_path = os.path.join(self.keys_dir, f'private-{kid}.pem')
        public_key_path = os.path.join(self.keys_dir, f'public-{kid}.pem')

        if not (os.path.exists(private_key_path) and os.path.exists(public_key_path)):
            return self.generate_key_pair()

        # Load private key
        with open(private_key_path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )

        # Load public key
        with open(public_key_path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )

        self.kid = kid
        return kid

    def get_jwks(self):
        """Get JSON Web Key Set"""
        if not self.public_key:
            self.generate_key_pair()

        public_numbers = self.public_key.public_numbers()
        return {
            'keys': [{
                'kid': self.kid,
                'kty': 'RSA',
                'alg': 'RS256',
                'use': 'sig',
                'n': self._int_to_base64(public_numbers.n),
                'e': self._int_to_base64(public_numbers.e),
            }]
        }

    def _int_to_base64(self, value):
        """Convert an integer to a Base64URL-encoded string"""
        value_hex = format(value, 'x')
        if len(value_hex) % 2:
            value_hex = '0' + value_hex
        value_bytes = bytes.fromhex(value_hex)
        import base64
        return base64.urlsafe_b64encode(value_bytes).rstrip(b'=').decode('ascii') 