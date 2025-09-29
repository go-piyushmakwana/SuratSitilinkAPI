import jwt
import datetime
from config import config


def generate_jwt(user: dict) -> str:
    payload = {
        'email': user['email'],
        'name': user.get('name'),
        'exp': datetime.datetime.now(datetime.timezone.utc) + config.JWT_EXPIRATION_DELTA,
        'iat': datetime.datetime.now(datetime.timezone.utc)
    }

    # Encode the token using the secret key defined in the configuration
    token = jwt.encode(
        payload,
        config.JWT_SECRET_KEY,
        algorithm="HS256"
    )
    return token
