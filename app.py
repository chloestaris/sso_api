# app.py
from flask import Flask, request, jsonify, render_template_string
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import os
import sys
from flask_swagger_ui import get_swaggerui_blueprint
import json
from oauth_server import config_oauth
from oauth_models import OAuth2Client
from models import db, User
from sqlalchemy import text

# Initialize Flask app
app = Flask(__name__, instance_relative_config=True)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# For development only - allow OAuth2 over HTTP
os.environ['AUTHLIB_INSECURE_TRANSPORT'] = '1'

# Create instance directory if it doesn't exist
os.makedirs(app.instance_path, exist_ok=True)

# Create static directory if it doesn't exist
static_dir = os.path.join(app.root_path, 'static')
os.makedirs(static_dir, exist_ok=True)

# Initialize SQLAlchemy
db.init_app(app)

# Configure OAuth2 server
oauth_server, require_oauth, key_manager = config_oauth(app)
app.key_manager = key_manager  # Attach key_manager to app instance

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
            # Add logging
            sys.stdout.write(f"\nDecoding token: {token[:10]}...\n")
            sys.stdout.flush()
            
            # Check if algorithm is configured
            if not app.config.get('JWT_ALGORITHM'):
                return jsonify({'message': 'JWT algorithm not configured'}), 500
            
            # Decode using RSA public key with correct algorithm
            data = jwt.decode(token, app.config['JWT_PUBLIC_KEY'], algorithms=["RS256","HS256"])
            
            # Add logging
            sys.stdout.write(f"Token decoded successfully. User ID: {data.get('user_id')}\n")
            sys.stdout.flush()
            
            current_user = User.query.filter_by(id=data['user_id']).first()
            if not current_user:
                return jsonify({'message': 'User not found'}), 401
                
            # Add logging
            sys.stdout.write(f"User found: {current_user.username}\n")
            sys.stdout.flush()
            
            return f(current_user, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({'message': f'Invalid token: {str(e)}'}), 401
        except Exception as e:
            sys.stdout.write(f"Unexpected error in token validation: {str(e)}\n")
            sys.stdout.flush()
            return jsonify({'message': f'Error validating token: {str(e)}'}), 401
            
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
        # Check if algorithm is configured
        if not app.config.get('JWT_ALGORITHM'):
            return jsonify({'message': 'JWT algorithm not configured'}), 500
            
        # Generate token using RSA private key
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),
            'iat': datetime.datetime.utcnow(),
            'kid': key_manager.kid  # Add key ID for key rotation support
        }, app.config['JWT_PRIVATE_KEY'], algorithm=app.config['JWT_ALGORITHM'])
        
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
        # Check if algorithm is configured
        if not app.config.get('JWT_ALGORITHM'):
            return jsonify({'message': 'JWT algorithm not configured'}), 500
            
        data = jwt.decode(token, app.config['JWT_PUBLIC_KEY'], algorithms=["RS256","HS256"])
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

# OAuth2 endpoints
@app.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    # Get user from JWT token
    token = None
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization']
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
    
    if not token:
        return jsonify({'message': 'Token is missing'}), 401
    
    try:
        # Add logging
        sys.stdout.write(f"\nAuthorize endpoint - Decoding token: {token[:10]}...\n")
        sys.stdout.flush()
        
        # Check if algorithm is configured
        if not app.config.get('JWT_ALGORITHM'):
            return jsonify({'message': 'JWT algorithm not configured'}), 500
        
        # Use RSA public key for verification
        data = jwt.decode(token, app.config['JWT_PUBLIC_KEY'], algorithms=["RS256","HS256"])
        
        # Add logging
        sys.stdout.write(f"Token decoded successfully. User ID: {data.get('user_id')}\n")
        sys.stdout.flush()
        
        current_user = User.query.filter_by(id=data['user_id']).first()
        if not current_user:
            return jsonify({'message': 'User not found'}), 401
            
        # Add logging
        sys.stdout.write(f"User found: {current_user.username}\n")
        sys.stdout.flush()
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({'message': f'Invalid token: {str(e)}'}), 401
    except Exception as e:
        sys.stdout.write(f"Unexpected error in authorize endpoint: {str(e)}\n")
        sys.stdout.flush()
        return jsonify({'message': f'Error validating token: {str(e)}'}), 401

    if request.method == 'GET':
        try:
            grant = oauth_server.get_consent_grant(end_user=current_user)
            return render_template_string('''
                <form action="" method="post">
                    <p>Client {{ client.client_name }} is requesting access to your account.</p>
                    <p>Requested scopes: {{ scopes }}</p>
                    <input type="submit" name="confirm" value="Authorize">
                    <input type="submit" name="confirm" value="Deny">
                </form>
            ''', client=grant.client, scopes=grant.request.scope)
        except Exception as e:
            return jsonify(error=str(e)), 400

    confirmed = request.form.get('confirm') == 'Authorize'
    if confirmed:
        # granted by resource owner
        return oauth_server.create_authorization_response(grant_user=current_user)
    # denied by resource owner
    return oauth_server.create_authorization_response(grant_user=None)

@app.route('/oauth/token', methods=['POST'])
def issue_token():
    return oauth_server.create_token_response()

@app.route('/.well-known/jwks.json')
def jwks():
    return jsonify(key_manager.get_jwks())

@app.route('/oauth/userinfo')
@require_oauth('profile')
def userinfo():
    try:
        # Add debug logging
        app.logger.debug("=== Userinfo Endpoint ===")
        app.logger.debug(f"Headers: {dict(request.headers)}")
        
        token = getattr(request, 'oauth_token', None)
        app.logger.debug(f"Token from request: {token}")
        
        if not token:
            app.logger.debug("No oauth_token found on request object")
            return jsonify({'error': 'No token found'}), 401
            
        user = token.user
        app.logger.debug(f"User from token: {user}")
        
        if not user:
            app.logger.debug("No user associated with token")
            return jsonify({'error': 'No user associated with token'}), 401
            
        response_data = {
            'sub': str(user.id),
            'username': user.username,
            'email': user.email,
            'email_verified': user.email_verified
        }
        app.logger.debug(f"Returning user info: {response_data}")
        return jsonify(response_data)
    except Exception as e:
        app.logger.error(f"Error in userinfo endpoint: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Client management endpoints
@app.route('/oauth/clients', methods=['GET'])
@token_required
def list_clients(current_user):
    """List all OAuth2 clients for the current user."""
    clients = OAuth2Client.query.filter_by(user_id=current_user.id).all()
    return jsonify([{
        'client_id': client.client_id,
        'client_name': client.client_metadata.get('client_name'),
        'redirect_uris': client.client_metadata.get('redirect_uris'),
        'grant_types': client.client_metadata.get('grant_types'),
        'response_types': client.client_metadata.get('response_types'),
        'scope': client.client_metadata.get('scope'),
    } for client in clients])

@app.route('/oauth/clients', methods=['POST'])
@token_required
def create_client(current_user):
    """Create a new OAuth2 client."""
    if not current_user.email_verified:
        return jsonify({'error': 'email_not_verified'}), 403

    data = request.get_json()
    client = OAuth2Client(
        user_id=current_user.id,
        client_name=data.get('client_name'),
        redirect_uris=data.get('redirect_uris', []),
        grant_types=data.get('grant_types', []),
        response_types=data.get('response_types', []),
        scope=data.get('scope', '')
    )
    db.session.add(client)
    db.session.commit()

    return jsonify({
        'client_id': client.client_id,
        'client_secret': client.client_secret,
        'client_name': client.client_metadata.get('client_name'),
        'redirect_uris': client.client_metadata.get('redirect_uris'),
        'grant_types': client.client_metadata.get('grant_types'),
        'response_types': client.client_metadata.get('response_types'),
        'scope': client.client_metadata.get('scope'),
    }), 201

@app.route('/oauth/init-admin-client', methods=['POST'])
@token_required
def init_admin_client(current_user):
    """Initialize the admin OAuth2 client."""
    if not current_user.email_verified:
        return jsonify({'message': 'Email verification required'}), 403

    data = request.get_json()
    client = OAuth2Client(
        user_id=current_user.id,
        client_name=data.get('client_name', 'Admin Client'),
        redirect_uris=[data.get('redirect_uri')],
        grant_types=['authorization_code', 'refresh_token'],
        response_types=['code'],
        scope='profile manage_clients'
    )
    db.session.add(client)
    db.session.commit()

    return jsonify({
        'client_id': client.client_id,
        'client_secret': client.client_secret,
        'client_name': client.client_metadata.get('client_name'),
        'redirect_uris': client.client_metadata.get('redirect_uris'),
        'grant_types': client.client_metadata.get('grant_types'),
        'response_types': client.client_metadata.get('response_types'),
        'scope': client.client_metadata.get('scope'),
    }), 201

# Create a simple swagger.json file instead of generating it dynamically
swagger_data = {
  "openapi": "3.0.0",
  "info": {
    "title": "Flask Authentication API with OAuth2/SSO",
    "description": "API for user authentication with email verification and OAuth2/SSO support",
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
      },
      "oauth2Auth": {
        "type": "oauth2",
        "flows": {
          "authorizationCode": {
            "authorizationUrl": "http://localhost:5000/oauth/authorize",
            "tokenUrl": "http://localhost:5000/oauth/token",
            "scopes": {
              "profile": "Access to user profile information",
              "manage_clients": "Manage OAuth2 clients"
            }
          }
        }
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
    },
    {
      "name": "OAuth2",
      "description": "OAuth2 and SSO operations"
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
                  "username": {"type": "string", "example": "testuser"},
                  "email": {"type": "string", "format": "email", "example": "user@example.com"},
                  "password": {"type": "string", "format": "password", "example": "password123"}
                },
                "required": ["username", "email", "password"]
              }
            }
          }
        },
        "responses": {
          "201": {"description": "User created successfully"},
          "400": {"description": "Bad request - missing fields or user already exists"}
        }
      }
    },
    "/login": {
      "post": {
        "tags": ["Authentication"],
        "summary": "Login to get a JWT token",
        "requestBody": {
          "required": True,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "username": {"type": "string", "example": "testuser"},
                  "password": {"type": "string", "format": "password", "example": "password123"}
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
                    "message": {"type": "string", "example": "Login successful"},
                    "token": {"type": "string", "example": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."},
                    "expires_in": {"type": "integer", "example": 86400},
                    "email_verified": {"type": "boolean", "example": True}
                  }
                }
              }
            }
          },
          "401": {"description": "Invalid credentials"}
        }
      }
    },
    "/oauth/authorize": {
      "get": {
        "tags": ["OAuth2"],
        "summary": "OAuth2 authorization endpoint",
        "security": [{"bearerAuth": []}],
        "parameters": [
          {
            "name": "response_type",
            "in": "query",
            "required": True,
            "schema": {"type": "string", "enum": ["code"]},
            "description": "OAuth2 response type (must be 'code')"
          },
          {
            "name": "client_id",
            "in": "query",
            "required": True,
            "schema": {"type": "string"},
            "description": "OAuth2 client ID"
          },
          {
            "name": "redirect_uri",
            "in": "query",
            "required": True,
            "schema": {"type": "string"},
            "description": "Callback URL for the authorization code"
          },
          {
            "name": "scope",
            "in": "query",
            "required": True,
            "schema": {"type": "string"},
            "description": "Space-separated list of requested scopes"
          },
          {
            "name": "code_challenge",
            "in": "query",
            "required": True,
            "schema": {"type": "string"},
            "description": "PKCE code challenge"
          },
          {
            "name": "code_challenge_method",
            "in": "query",
            "required": True,
            "schema": {"type": "string", "enum": ["S256"]},
            "description": "PKCE code challenge method (must be 'S256')"
          }
        ],
        "responses": {
          "200": {"description": "Authorization form displayed"},
          "401": {"description": "Unauthorized"},
          "400": {"description": "Invalid request"}
        }
      },
      "post": {
        "tags": ["OAuth2"],
        "summary": "Submit OAuth2 authorization decision",
        "security": [{"bearerAuth": []}],
        "requestBody": {
          "required": True,
          "content": {
            "application/x-www-form-urlencoded": {
              "schema": {
                "type": "object",
                "properties": {
                  "confirm": {"type": "string", "enum": ["Authorize", "Deny"]}
                },
                "required": ["confirm"]
              }
            }
          }
        },
        "responses": {
          "302": {"description": "Redirect to client with authorization code or error"},
          "401": {"description": "Unauthorized"},
          "400": {"description": "Invalid request"}
        }
      }
    },
    "/oauth/token": {
      "post": {
        "tags": ["OAuth2"],
        "summary": "Exchange authorization code for access token",
        "requestBody": {
          "required": True,
          "content": {
            "application/x-www-form-urlencoded": {
              "schema": {
                "type": "object",
                "properties": {
                  "grant_type": {"type": "string", "enum": ["authorization_code"]},
                  "code": {"type": "string"},
                  "redirect_uri": {"type": "string"},
                  "code_verifier": {"type": "string"}
                },
                "required": ["grant_type", "code", "redirect_uri", "code_verifier"]
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Access token issued",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "access_token": {"type": "string"},
                    "token_type": {"type": "string", "example": "Bearer"},
                    "expires_in": {"type": "integer"},
                    "scope": {"type": "string"}
                  }
                }
              }
            }
          },
          "400": {"description": "Invalid request"}
        }
      }
    },
    "/oauth/userinfo": {
      "get": {
        "tags": ["OAuth2"],
        "summary": "Get user information",
        "security": [{"oauth2Auth": ["profile"]}],
        "responses": {
          "200": {
            "description": "User information",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "sub": {"type": "string"},
                    "username": {"type": "string"},
                    "email": {"type": "string"},
                    "email_verified": {"type": "boolean"}
                  }
                }
              }
            }
          },
          "401": {"description": "Unauthorized"}
        }
      }
    },
    "/oauth/clients": {
      "get": {
        "tags": ["OAuth2"],
        "summary": "List OAuth2 clients",
        "security": [{"bearerAuth": []}],
        "responses": {
          "200": {
            "description": "List of OAuth2 clients",
            "content": {
              "application/json": {
                "schema": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "client_id": {"type": "string"},
                      "client_name": {"type": "string"},
                      "redirect_uris": {"type": "array", "items": {"type": "string"}},
                      "grant_types": {"type": "array", "items": {"type": "string"}},
                      "response_types": {"type": "array", "items": {"type": "string"}},
                      "scope": {"type": "string"}
                    }
                  }
                }
              }
            }
          },
          "401": {"description": "Unauthorized"}
        }
      },
      "post": {
        "tags": ["OAuth2"],
        "summary": "Create new OAuth2 client",
        "security": [{"bearerAuth": []}],
        "requestBody": {
          "required": True,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "client_name": {"type": "string"},
                  "redirect_uris": {"type": "array", "items": {"type": "string"}},
                  "grant_types": {"type": "array", "items": {"type": "string"}},
                  "response_types": {"type": "array", "items": {"type": "string"}},
                  "scope": {"type": "string"}
                },
                "required": ["client_name", "redirect_uris"]
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "OAuth2 client created",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "client_id": {"type": "string"},
                    "client_secret": {"type": "string"},
                    "client_name": {"type": "string"},
                    "redirect_uris": {"type": "array", "items": {"type": "string"}},
                    "grant_types": {"type": "array", "items": {"type": "string"}},
                    "response_types": {"type": "array", "items": {"type": "string"}},
                    "scope": {"type": "string"}
                  }
                }
              }
            }
          },
          "401": {"description": "Unauthorized"},
          "403": {"description": "Email not verified"}
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

@app.route('/health')
def health_check():
    try:
        # Test database connection
        db.session.execute(text('SELECT 1'))
        db.session.commit()
        
        # Test instance directory
        if not os.path.exists(app.instance_path):
            raise Exception("Instance directory not found")
        
        # Test instance directory is writable
        if not os.access(app.instance_path, os.W_OK):
            raise Exception("Instance directory is not writable")
        
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'instance_path': 'accessible'
        }), 200
    except Exception as e:
        app.logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

if __name__ == '__main__':
    sys.stdout.write("\n=== Starting Flask Authentication API with Email Verification ===\n")
    sys.stdout.flush()
    app.run(debug=True)