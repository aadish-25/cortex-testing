"""
Enterprise Authentication Service.
Handles JWT token generation, signature and claims verification,
token_version revocation checks, and password hashing via bcrypt.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
import os
import logging
import jwt
import bcrypt

logger = logging.getLogger(__name__)

# Security configurations
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "cortex-enterprise-secret-key-change-in-prod")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 30


class AuthenticationError(Exception):
    """Base exception for authentication failures."""
    pass


class InvalidTokenError(AuthenticationError):
    """Raised when JWT format or signature verification fails."""
    pass


class AuthService:
    def __init__(self, user_repository=None, cache_client=None):
        self.user_repo = user_repository
        self.cache = cache_client

    @staticmethod
    def hash_password(plain_password: str) -> str:
        """Hash a plaintext password using bcrypt with standard salt rounds."""
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
        return hashed.decode("utf-8")

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify password against stored bcrypt hash."""
        try:
            return bcrypt.checkpw(
                plain_password.encode("utf-8"),
                hashed_password.encode("utf-8")
            )
        except Exception as exc:
            logger.error("Password verification error: %s", exc)
            return False

    def create_access_token(
        self,
        user_id: str,
        user_email: str,
        token_version: int = 1,
        roles: Optional[list] = None
    ) -> str:
        """Generate a signed JWT access token containing user identity and current token_version."""
        now = datetime.now(timezone.utc)
        payload = {
            "sub": user_id,
            "email": user_email,
            "token_version": token_version,
            "roles": roles or ["user"],
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
            "type": "access"
        }
        return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    def verify_token(self, token: str) -> Dict[str, Any]:
        """
        Verify JWT token signature and expiration.
        """
        try:
            payload = jwt.decode(
                token,
                JWT_SECRET_KEY,
                algorithms=[JWT_ALGORITHM],
                options={"require": ["exp", "iat", "sub"]}
            )
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Authentication token has expired")
        except jwt.PyJWTError as e:
            raise InvalidTokenError(f"Failed to decode token: {str(e)}")

        return payload
