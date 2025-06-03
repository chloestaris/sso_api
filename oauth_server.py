from authlib.integrations.flask_oauth2 import AuthorizationServer, ResourceProtector
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc7523 import JWTBearerGrant
from authlib.jose import JsonWebKey
from werkzeug.security import gen_salt
from models import db, User
from oauth_models import OAuth2Client, OAuth2Token, OAuth2AuthorizationCode
from key_manager import KeyManager
import time

class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = [
        'client_secret_basic',
        'client_secret_post',
        'none',
    ]

    def save_authorization_code(self, code, request):
        code_challenge = request.data.get('code_challenge')
        code_challenge_method = request.data.get('code_challenge_method')
        
        auth_code = OAuth2AuthorizationCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=request.user.id,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method
        )
        db.session.add(auth_code)
        db.session.commit()
        return auth_code

    def query_authorization_code(self, code, client):
        auth_code = OAuth2AuthorizationCode.query.filter_by(
            code=code,
            client_id=client.client_id
        ).first()
        if auth_code and not auth_code.is_expired():
            return auth_code

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return User.query.get(authorization_code.user_id)


class RefreshTokenGrant(grants.RefreshTokenGrant):
    def authenticate_refresh_token(self, refresh_token):
        token = OAuth2Token.query.filter_by(refresh_token=refresh_token).first()
        if token and token.is_refresh_token_active():
            return token

    def authenticate_user(self, credential):
        return User.query.get(credential.user_id)

    def revoke_old_credential(self, credential):
        credential.revoked = True
        db.session.add(credential)
        db.session.commit()


def config_oauth(app):
    # Initialize key manager and generate keys
    key_manager = KeyManager()
    try:
        kid = key_manager.generate_key_pair()
    except Exception as e:
        app.logger.error(f"Error generating key pair: {str(e)}")
        raise

    # Configure JWT settings in Flask app config
    app.config['JWT_PRIVATE_KEY'] = key_manager.private_key
    app.config['JWT_PUBLIC_KEY'] = key_manager.public_key
    app.config['JWT_PRIVATE_KEY_PATH'] = f'keys/private-{kid}.pem'
    app.config['JWT_PUBLIC_KEY_PATH'] = f'keys/public-{kid}.pem'
    app.config['JWT_ALGORITHM'] = 'RS256'

    # Query functions
    def query_client(client_id):
        return OAuth2Client.query.filter_by(client_id=client_id).first()

    def save_token(token_data, request):
        if request.user:
            user_id = request.user.id
        else:
            user_id = None

        client = request.client
        # Ensure token_type is 'bearer' but don't duplicate it
        if 'token_type' not in token_data:
            token_data['token_type'] = 'bearer'
            
        # Set default expiry if not provided
        if 'expires_in' not in token_data:
            token_data['expires_in'] = 3600  # 1 hour default
            
        token = OAuth2Token(
            client_id=client.client_id,
            user_id=user_id,
            **token_data
        )
        db.session.add(token)
        db.session.commit()
        return token

    # Initialize OAuth2 server
    server = AuthorizationServer(
        app,
        query_client=query_client,
        save_token=save_token
    )

    # Support PKCE
    server.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=True)])
    server.register_grant(RefreshTokenGrant)

    # Resource protector
    require_oauth = ResourceProtector()

    # Create BearerTokenValidator class
    class BearerTokenValidator:
        TOKEN_TYPE = 'bearer'
        
        def __init__(self):
            self.realm = 'Bearer'

        def authenticate_token(self, token_string):
            with app.app_context():  # Add app context
                app.logger.debug(f"Authenticating token: {token_string}")
                token = OAuth2Token.query.filter_by(access_token=token_string).first()
                if token:
                    app.logger.debug(f"Token found in database. User ID: {token.user_id}")
                    app.logger.debug(f"Token scopes: {token.scope}")
                    app.logger.debug(f"Token issued at: {token.issued_at}, expires in: {token.expires_in}")
                    if not token.is_expired() and not token.is_revoked():
                        return token
                    else:
                        app.logger.debug(f"Token validation failed - Expired: {token.is_expired()}, Revoked: {token.is_revoked()}")
                else:
                    app.logger.debug("Token not found in database")
            return None

        def request_invalid(self, request):
            app.logger.debug("Checking if request is invalid")
            return False

        def token_revoked(self, token):
            revoked = token.revoked if token else True
            app.logger.debug(f"Checking if token is revoked: {revoked}")
            return revoked
        
        def validate_request(self, request):
            """Validate the request object."""
            auth = request.headers.get('Authorization')
            app.logger.debug(f"Authorization header: {auth}")
            if not auth:
                app.logger.debug("No Authorization header found")
                return False
            try:
                auth_type, token = auth.split(None, 1)
                app.logger.debug(f"Auth type: {auth_type}, Token: {token[:10]}...")
                if auth_type.lower() != 'bearer':
                    app.logger.debug("Not a bearer token")
                    return False
                token_obj = self.authenticate_token(token)
                if token_obj:
                    app.logger.debug("Token validated successfully")
                    request.oauth_token = token_obj  # Direct assignment instead of setattr
                    return True
                app.logger.debug("Token validation failed")
                return False
            except ValueError:
                app.logger.debug("Invalid Authorization header format")
                return False
        
        def validate_token(self, token, scopes, request):
            """Validate the token."""
            app.logger.debug(f"Validating token with scopes: {scopes}")
            if not token:
                app.logger.debug("No token provided")
                return False
            if token.revoked:
                app.logger.debug("Token is revoked")
                return False
            if not token.is_valid():
                app.logger.debug("Token is not valid")
                return False
            
            # Check scopes
            if scopes:
                token_scopes = set(token.get_scope().split())
                app.logger.debug(f"Token scopes: {token_scopes}")
                for scope in scopes:
                    if scope not in token_scopes:
                        app.logger.debug(f"Missing required scope: {scope}")
                        return False
            
            # Set token on request object
            app.logger.debug("Token validation successful")
            request.oauth_token = token  # Use the token parameter
            return True

    # Register the token validator
    bearer_validator = BearerTokenValidator()
    require_oauth.register_token_validator(bearer_validator)

    # Add to app context
    app.require_oauth = require_oauth

    return server, require_oauth, key_manager 