from models import db
import time
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7636 import CodeChallenge
from werkzeug.security import gen_salt

class OAuth2Client(db.Model):
    __tablename__ = 'oauth2_client'

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(48), unique=True, nullable=False)
    client_secret = db.Column(db.String(120), unique=True, nullable=False)
    client_id_issued_at = db.Column(db.Integer, nullable=False, default=time.time)
    client_secret_expires_at = db.Column(db.Integer, nullable=False, default=0)

    client_metadata = db.Column(db.JSON, nullable=False, default=dict)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')

    def __init__(self, user_id, **kwargs):
        self.user_id = user_id
        self.client_id = gen_salt(24)
        if 'client_secret' not in kwargs:
            self.client_secret = gen_salt(48)
        else:
            self.client_secret = kwargs.pop('client_secret')
        
        self.client_metadata = kwargs
        self.client_metadata.setdefault('client_name', '')
        self.client_metadata.setdefault('client_uri', '')
        self.client_metadata.setdefault('grant_types', [])
        self.client_metadata.setdefault('redirect_uris', [])
        self.client_metadata.setdefault('response_types', [])
        self.client_metadata.setdefault('scope', '')
        self.client_metadata.setdefault('token_endpoint_auth_method', 'client_secret_basic')

    def get_client_id(self):
        return self.client_id

    def get_default_redirect_uri(self):
        return self.client_metadata.get('redirect_uris')[0]

    def get_allowed_scope(self, scope):
        if not scope:
            return ''
        allowed = set(scope.split())
        return ' '.join(allowed)

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self.client_metadata.get('redirect_uris', [])

    def check_client_secret(self, client_secret):
        return self.client_secret == client_secret

    def check_endpoint_auth_method(self, method, endpoint):
        if endpoint == 'token':
            return method == self.client_metadata.get('token_endpoint_auth_method')
        return True

    def check_response_type(self, response_type):
        return response_type in self.client_metadata.get('response_types', [])

    def check_grant_type(self, grant_type):
        return grant_type in self.client_metadata.get('grant_types', [])


class OAuth2Token(db.Model):
    __tablename__ = 'oauth2_token'

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(48), db.ForeignKey('oauth2_client.client_id', ondelete='CASCADE'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    token_type = db.Column(db.String(40))
    access_token = db.Column(db.String(255), unique=True)
    refresh_token = db.Column(db.String(255), unique=True)
    scope = db.Column(db.Text, default='')
    revoked = db.Column(db.Boolean, default=False)
    issued_at = db.Column(db.Integer, nullable=False, default=lambda: int(time.time()))
    expires_in = db.Column(db.Integer, nullable=False, default=0)

    user = db.relationship('User')
    client = db.relationship('OAuth2Client')

    def get_scope(self):
        return self.scope

    def get_expires_in(self):
        return self.expires_in

    def is_expired(self):
        return self.issued_at + self.expires_in < time.time()

    def is_revoked(self):
        return self.revoked

    def is_valid(self):
        return not self.is_expired() and not self.is_revoked()

    def check_client_grant_type(self, grant_type):
        if not self.client_id:
            return False
        client = OAuth2Client.query.get(self.client_id)
        return client and grant_type in client.client_metadata.get('grant_types', [])

    def get_user(self):
        return self.user

    def get_client(self):
        return self.client


class OAuth2AuthorizationCode(db.Model):
    __tablename__ = 'oauth2_code'

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(120), unique=True, nullable=False)
    client_id = db.Column(db.String(48))
    redirect_uri = db.Column(db.Text, default='')
    response_type = db.Column(db.Text, default='')
    scope = db.Column(db.Text, default='')
    auth_time = db.Column(db.Integer, nullable=False, default=time.time)
    expires_in = db.Column(db.Integer, nullable=False, default=600)  # 10 minutes
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')

    code_challenge = db.Column(db.String(128))
    code_challenge_method = db.Column(db.String(10))

    def is_expired(self):
        return self.auth_time + self.expires_in < time.time()

    def get_redirect_uri(self):
        return self.redirect_uri
        
    def get_scope(self):
        return self.scope

    def get_auth_time(self):
        return self.auth_time