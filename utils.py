import jwt
import datetime
from config import config

def generate_jwt(user: dict) -> str:
    """Generates a JWT token for the given user data."""
    # Ensure the user dictionary is serializable (e.g., convert ObjectId to str if needed)
    # The payload contains basic user info and expiration time
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
