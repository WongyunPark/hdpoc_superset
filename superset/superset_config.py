from flask_appbuilder.security.manager import AUTH_OAUTH
from superset.custom.CustomSsoSecurityManager import CustomSsoSecurityManager
import os

CUSTOM_SECURITY_MANAGER = CustomSsoSecurityManager

SECRET_KEY = 'hdwpoctest'


SQLALCHEMY_DATABASE_URI = os.environ.get("SQLALCHEMY_DATABASE_URI")

# Flask-WTF flag for CSRF
WTF_CSRF_ENABLED = True
# Add endpoints that need to be exempt from CSRF protection
WTF_CSRF_EXEMPT_LIST = []
# A CSRF token that expires in 1 year
WTF_CSRF_TIME_LIMIT = 60 * 60 * 24 * 365

# Set this API key to enable Mapbox visualizations
MAPBOX_API_KEY = ''
from datetime import timedelta
from flask import session, Flask
PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(os.environ.get("SESSION_TIME")))
def make_session_permanent():
    '''
    Enable maxAge for the cookie 'session'
    '''
    session.permanent = True
def FLASK_APP_MUTATOR(app: Flask) -> None:
    app.before_request_funcs.setdefault(None, []).append(make_session_permanent)

# Set the authentication type to OAuth
AUTH_TYPE = AUTH_OAUTH

OAUTH_PROVIDERS = [
    {
        "name": "google",
        "icon": "fa-google",
        "token_key": "access_token",
        "remote_app": {
            "client_id": os.environ.get("GOOGLE_KEY"),
            "client_secret": os.environ.get("GOOGLE_SECRET"),
            "api_base_url": "https://www.googleapis.com/oauth2/v2/",
            "client_kwargs":{
                "scope": "https://www.googleapis.com/auth/devstorage.read_write https://www.googleapis.com/auth/devstorage.read_only https://www.googleapis.com/auth/devstorage.full_control https://www.googleapis.com/auth/drive.metadata.readonly https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/bigquery openid"
            },
            "request_token_url": None,
            "access_token_url": "https://accounts.google.com/o/oauth2/token",
            "authorize_url": "https://accounts.google.com/o/oauth2/auth",
            "jwks_uri" : "https://www.googleapis.com/oauth2/v3/certs"
        }
    }
]

# Will allow user self registration, allowing to create Flask users from Authorized User
AUTH_USER_REGISTRATION = True
AUTH_ROLE_ADMIN = 'Admin'
AUTH_USER_REGISTRATION_ROLE = "Admin"
# The default user self registration role
# AUTH_USER_REGISTRATION_ROLE = "Public"