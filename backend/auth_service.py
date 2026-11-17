"""
Enterprise Authentication Service.
Handles JWT token generation, signature and claims verification,
token_version validation for immediate revocation, and password hashing via bcrypt.
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


class TokenRevokedError(AuthenticationError):
    """Raised when token_version mismatch indicates token has been revoked."""
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

    def verify_token(self, token: str, validate_revocation: bool = True) -> Dict[str, Any]:
        """
        Verify JWT token validity and ensure it has not been revoked via token_version.
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

        if validate_revocation:
            user_id = payload.get("sub")
            token_ver = payload.get("token_version")
            self._check_token_version(user_id, token_ver)

        return payload

    def _check_token_version(self, user_id: str, token_version: Optional[int]) -> None:
        """
        Validate token_version against current user record in database/cache.
        Allows instant revocation of all active sessions upon logout or password reset.
        """
        if token_version is None:
            raise TokenRevokedError("Missing token_version claim in token payload")

        current_version = None
        if self.cache:
            current_version = self.cache.get(f"user:token_version:{user_id}")

        if current_version is None and self.user_repo:
            user = self.user_repo.find_by_id(user_id)
            if user:
                current_version = user.token_version

        if current_version is not None and token_version < int(current_version):
            logger.warning(
                "Revoked session access attempt for user %s (token version: %d, current: %d)",
                user_id, token_version, current_version
            )
            raise TokenRevokedError("Session has been revoked. Please sign in again.")

    def revoke_all_sessions(self, user_id: str) -> int:
        """Increment token_version to invalidate all existing tokens for this user immediately."""
        new_version = 1
        if self.user_repo:
            new_version = self.user_repo.increment_token_version(user_id)
        if self.cache:
            self.cache.set(f"user:token_version:{user_id}", new_version)
        logger.info("Revoked all sessions for user %s; new token_version=%d", user_id, new_version)
        return new_version
