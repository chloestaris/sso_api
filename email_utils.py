# email_utils.py
import jwt
import datetime
import sys

def setup_email_verification(app):
    """Setup email verification functions for the app"""
    
    def generate_verification_token(user_id, email):
        """Generate token for email verification"""
        # Check if algorithm is configured
        if not app.config.get('JWT_ALGORITHM'):
            raise ValueError('JWT algorithm not configured')
            
        payload = {
            'user_id': user_id,
            'email': email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),
            'iat': datetime.datetime.utcnow(),
            'kid': app.key_manager.kid  # Add key ID for key rotation support
        }
        return jwt.encode(payload, app.config['JWT_PRIVATE_KEY'], algorithm=app.config['JWT_ALGORITHM'])
    
    def send_verification_email(user, verification_token):
        """Mock sending a verification email"""
        verification_url = f"http://localhost:5000/verify-email/{verification_token}"
        
        email_content = f"""
============================================================
                    VERIFICATION EMAIL
============================================================
To: {user.email}
Subject: Verify your email address

Hello,

Please verify your email address by clicking the link below:

{verification_url}

This link will expire in 24 hours.

Thank you,
The API Team
============================================================
"""
        # Force print to stdout and flush
        sys.stdout.write(email_content + "\n")
        sys.stdout.flush()
        
        return True
    
    # Return the functions so they can be imported elsewhere
    return generate_verification_token, send_verification_email