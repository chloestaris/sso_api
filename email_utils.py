# email_utils.py
import jwt
import datetime
import sys

def setup_email_verification(app):
    """Setup email verification functions for the app"""
    
    def generate_verification_token(user_id, email):
        """Generate token for email verification"""
        payload = {
            'user_id': user_id,
            'email': email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),
            'iat': datetime.datetime.utcnow()
        }
        return jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")
    
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