import os
from flask_httpauth import HTTPTokenAuth
from itsdangerous import TimedJSONWebSignatureSerializer as JsonWebToken

# Retrieve secret keys from environment variables
jwt_secret_key = os.environ.get('JWT_SECRET_KEY', 'default_secret_key')
refresh_jwt_secret_key = os.environ.get('REFRESH_JWT_SECRET_KEY', 'default_refresh_key')

# JWT creation with the secret key from environment variable
jwt = JsonWebToken(jwt_secret_key, expires_in=300) # 5 minutes
# Refresh token creation with a different secret key from environment variable
refresh_jwt = JsonWebToken(refresh_jwt_secret_key, expires_in=600) # 10 minutes

# Auth object creation
auth = HTTPTokenAuth("Bearer")


