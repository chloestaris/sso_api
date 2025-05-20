# app.py
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import os
import sys

# Create and configure the app
app = Flask(__name__, instance_relative_config=True)
app.config['SECRET_KEY'] =  'qucgon-xosbi5-paqhoz'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Create instance directory if it doesn't exist
os.makedirs(app.instance_path, exist_ok=True)

# Import models and initialize database
from models import db, User
db.init_app(app)

# Import email verification utilities
from email_utils import setup_email_verification
generate_verification_token, send_verification_email = setup_email_verification(app)

# Token authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
        except:
            return jsonify({'message': 'Token is invalid'}), 401
            
        return f(current_user, *args, **kwargs)
    
    return decorated

# Email verification decorator
def email_verified_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if not current_user.email_verified:
            return jsonify({'message': 'Email verification required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Check if required fields are present
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing required fields'}), 400
    
    # Check if user already exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already exists'}), 400
    
    # Hash the password
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    
    # Create new user
    new_user = User(
        username=data['username'],
        email=data['email'],
        password=hashed_password,
        email_verified=False
    )
    
    # Add user to database
    db.session.add(new_user)
    db.session.commit()
    
    # Generate and send verification email
    try:
        sys.stdout.write("\nSending verification email...\n")
        sys.stdout.flush()
        
        verification_token = generate_verification_token(new_user.id, new_user.email)
        send_verification_email(new_user, verification_token)
        
        sys.stdout.write(f"Verification email sent to {new_user.email}\n")
        sys.stdout.flush()
    except Exception as e:
        sys.stdout.write(f"Error sending verification email: {str(e)}\n")
        sys.stdout.flush()
    
    return jsonify({'message': 'User created successfully. Please check your console for verification link.'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing username or password'}), 400
    
    # Find user by username
    user = User.query.filter_by(username=data['username']).first()
    
    if not user:
        return jsonify({'message': 'Invalid credentials'}), 401
    
    # Check password
    if check_password_hash(user.password, data['password']):
        # Generate token
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'expires_in': 86400,  # 24 hours in seconds
            'email_verified': user.email_verified
        }), 200
    
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/verify-email/<token>', methods=['GET'])
def verify_email(token):
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        user_id = data['user_id']
        email = data['email']
        
        user = User.query.filter_by(id=user_id, email=email).first()
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        if user.email_verified:
            return jsonify({'message': 'Email already verified'}), 200
        
        user.email_verified = True
        db.session.commit()
        
        return jsonify({'message': 'Email verified successfully'}), 200
    except Exception as e:
        sys.stdout.write(f"Verification error: {str(e)}\n")
        sys.stdout.flush()
        return jsonify({'message': 'Invalid or expired verification link'}), 400

@app.route('/resend-verification', methods=['POST'])
@token_required
def resend_verification(current_user):
    if current_user.email_verified:
        return jsonify({'message': 'Email already verified'}), 400
    
    verification_token = generate_verification_token(current_user.id, current_user.email)
    send_verification_email(current_user, verification_token)
    
    return jsonify({'message': 'Verification email sent'}), 200

@app.route('/user', methods=['GET'])
@token_required
def get_user(current_user):
    user_data = {
        'id': current_user.id,
        'username': current_user.username,
        'email': current_user.email,
        'email_verified': current_user.email_verified,
        'created_at': current_user.created_at.isoformat()
    }
    
    return jsonify(user_data), 200

@app.route('/protected-verified', methods=['GET'])
@token_required
@email_verified_required
def protected_verified(current_user):
    return jsonify({'message': f'Hello {current_user.username}, your email is verified!'}), 200

@app.route('/test-verification/<username>', methods=['GET'])
def test_verification(username):
    """Test route to manually generate a verification link for a user"""
    user = User.query.filter_by(username=username).first()
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    sys.stdout.write(f"\nGenerating test verification email for {user.username}\n")
    sys.stdout.flush()
    
    verification_token = generate_verification_token(user.id, user.email)
    send_verification_email(user, verification_token)
    
    return jsonify({'message': 'Test verification email printed to console'}), 200

# Create tables before first request
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    sys.stdout.write("\n=== Starting Flask Authentication API with Email Verification ===\n")
    sys.stdout.flush()
    app.run(debug=True)