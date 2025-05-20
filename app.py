# app.py
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import os
import sys
from flask_swagger_ui import get_swaggerui_blueprint
import json

# Initialize Flask app
app = Flask(__name__, instance_relative_config=True)
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Create instance directory if it doesn't exist
os.makedirs(app.instance_path, exist_ok=True)

# Create static directory if it doesn't exist
static_dir = os.path.join(app.root_path, 'static')
os.makedirs(static_dir, exist_ok=True)

# Initialize SQLAlchemy
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

# Create a simple swagger.json file instead of generating it dynamically
swagger_data = {
  "openapi": "3.0.0",
  "info": {
    "title": "Flask Authentication API",
    "description": "API for user authentication with email verification",
    "version": "1.0.0"
  },
  "servers": [
    {
      "url": "http://localhost:5000",
      "description": "Development server"
    }
  ],
  "components": {
    "securitySchemes": {
      "bearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT"
      }
    }
  },
  "tags": [
    {
      "name": "Authentication",
      "description": "Authentication operations"
    },
    {
      "name": "User",
      "description": "User operations"
    },
    {
      "name": "Email Verification",
      "description": "Email verification operations"
    }
  ],
  "paths": {
    "/register": {
      "post": {
        "tags": ["Authentication"],
        "summary": "Register a new user",
        "requestBody": {
          "required": True,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "username": {
                    "type": "string",
                    "example": "testuser"
                  },
                  "email": {
                    "type": "string",
                    "format": "email",
                    "example": "user@example.com"
                  },
                  "password": {
                    "type": "string",
                    "format": "password",
                    "example": "password123"
                  }
                },
                "required": ["username", "email", "password"]
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "User created successfully"
          },
          "400": {
            "description": "Bad request - missing fields or user already exists"
          }
        }
      }
    },
    "/login": {
      "post": {
        "tags": ["Authentication"],
        "summary": "Login to get an access token",
        "requestBody": {
          "required": True,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "username": {
                    "type": "string",
                    "example": "testuser"
                  },
                  "password": {
                    "type": "string",
                    "format": "password",
                    "example": "password123"
                  }
                },
                "required": ["username", "password"]
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Login successful",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string",
                      "example": "Login successful"
                    },
                    "token": {
                      "type": "string",
                      "example": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                    },
                    "expires_in": {
                      "type": "integer",
                      "example": 86400
                    },
                    "email_verified": {
                      "type": "boolean",
                      "example": True
                    }
                  }
                }
              }
            }
          },
          "401": {
            "description": "Invalid credentials"
          }
        }
      }
    },
    "/verify-email/{token}": {
      "get": {
        "tags": ["Email Verification"],
        "summary": "Verify email address",
        "parameters": [
          {
            "name": "token",
            "in": "path",
            "required": True,
            "schema": {
              "type": "string"
            },
            "description": "Email verification token"
          }
        ],
        "responses": {
          "200": {
            "description": "Email verified successfully"
          },
          "400": {
            "description": "Invalid or expired token"
          },
          "404": {
            "description": "User not found"
          }
        }
      }
    },
    "/resend-verification": {
      "post": {
        "tags": ["Email Verification"],
        "summary": "Resend verification email",
        "security": [
          {
            "bearerAuth": []
          }
        ],
        "responses": {
          "200": {
            "description": "Verification email sent"
          },
          "400": {
            "description": "Email already verified"
          },
          "401": {
            "description": "Unauthorized"
          }
        }
      }
    },
    "/user": {
      "get": {
        "tags": ["User"],
        "summary": "Get current user profile",
        "security": [
          {
            "bearerAuth": []
          }
        ],
        "responses": {
          "200": {
            "description": "User profile",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "id": {
                      "type": "integer",
                      "example": 1
                    },
                    "username": {
                      "type": "string",
                      "example": "testuser"
                    },
                    "email": {
                      "type": "string",
                      "format": "email",
                      "example": "user@example.com"
                    },
                    "email_verified": {
                      "type": "boolean",
                      "example": True
                    },
                    "created_at": {
                      "type": "string",
                      "format": "date-time",
                      "example": "2023-05-20T12:34:56.789012"
                    }
                  }
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized"
          }
        }
      }
    },
    "/protected-verified": {
      "get": {
        "tags": ["User"],
        "summary": "Access protected resource (requires verified email)",
        "security": [
          {
            "bearerAuth": []
          }
        ],
        "responses": {
          "200": {
            "description": "Access granted"
          },
          "401": {
            "description": "Unauthorized"
          },
          "403": {
            "description": "Email verification required"
          }
        }
      }
    },
    "/test-verification/{username}": {
      "get": {
        "tags": ["Testing"],
        "summary": "Generate test verification email for a user",
        "parameters": [
          {
            "name": "username",
            "in": "path",
            "required": True,
            "schema": {
              "type": "string"
            },
            "description": "Username of the user"
          }
        ],
        "responses": {
          "200": {
            "description": "Test verification email sent"
          },
          "404": {
            "description": "User not found"
          }
        }
      }
    }
  }
}

# Save the swagger.json file
with open(os.path.join(static_dir, 'swagger.json'), 'w') as f:
    json.dump(swagger_data, f)

# Serve the static swagger.json file
@app.route('/static/swagger.json')
def serve_swagger():
    return jsonify(swagger_data)

# Create tables before first request
with app.app_context():
    db.create_all()

# Register Swagger UI Blueprint
SWAGGER_URL = '/api/docs'  # URL for exposing Swagger UI
API_URL = '/static/swagger.json'  # URL to access OpenAPI spec

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Flask Authentication API"
    }
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

if __name__ == '__main__':
    sys.stdout.write("\n=== Starting Flask Authentication API with Email Verification ===\n")
    sys.stdout.flush()
    app.run(debug=True)