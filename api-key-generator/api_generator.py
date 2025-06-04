import secrets
import string

def generate_api_key():
    """Generate a secure 32-character API key"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(32))
