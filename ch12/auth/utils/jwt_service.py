from datetime import datetime, timedelta
from pathlib import Path

import jwt
from jwt import (
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAlgorithmError,
    InvalidAudienceError,
    InvalidKeyError,
    InvalidSignatureError,
    InvalidTokenError,
    MissingRequiredClaimError,
)

from sqlalchemy.orm import Session

from fastapi.exceptions import HTTPException
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate

from auth.repository.models import password_context, User


def decode_token(token: str):
    public_key_text = (Path(__file__).parent / "../../public_key.pem").read_text()
    public_key = load_pem_x509_certificate(public_key_text.encode()).public_key()
    try:
        payload = jwt.decode(
            token,
            key=public_key,
            algorithms=["RS256"],
            audience="http://127.0.0.1:8000",
        )
        return payload['sub']  # Assuming 'sub' is the user ID
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail='token has expired')
    except jwt.InvalidAudienceError:
        raise HTTPException(status_code=400, detail='invalid audience')
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail='Invalid token')


def generate_access_token(sub):
    now = datetime.utcnow()
    payload = {
        "iss": "http://127.0.0.1:8000/",  
        "sub": str(sub),
        "aud": "http://127.0.0.1:8000",  
        "iat": now.timestamp(),
        "exp": (now + timedelta(hours=5)).timestamp(),
        "scope": "openid", 
    }

    private_key_text = Path("private_key.pem").read_text()
    private_key = serialization.load_pem_private_key(
        private_key_text.encode(),
        password=None,
    )
    return jwt.encode(payload=payload, key=private_key, algorithm="RS256")


def generate_refresh_token(sub):
    now = datetime.utcnow()
    payload = {
        "iss": "http://127.0.0.1:8000", 
        "sub": str(sub),
        "aud": "http://127.0.0.1:8000", 
        "iat": now.timestamp(),
        "exp": (now + timedelta(days=7)).timestamp(),
        "scope": "openid",
    }

    private_key_text = Path("private_key.pem").read_text()
    private_key = serialization.load_pem_private_key(
        private_key_text.encode(),
        password=None,
    )
    return jwt.encode(payload=payload, key=private_key, algorithm="RS256")


def verify_refresh_token(refresh_token: str, db: Session):
    try:
        # Decode the refresh token to get the user ID
        user_id = decode_token(refresh_token)

        # Check if the refresh token exists in the database
        user = db.query(User).filter(User.id == user_id, User.refresh_token == refresh_token).first()

        if user:
            return user_id
    except (
            ExpiredSignatureError,
            ImmatureSignatureError,
            InvalidAlgorithmError,
            InvalidAudienceError,
            InvalidKeyError,
            InvalidSignatureError,
            InvalidTokenError,
            MissingRequiredClaimError,
        ) as error:
        raise error(status_code=401, detail=str(error))


def generate_confirmation_token(sub):
    now = datetime.utcnow()
    payload = {
        "iss": "http://127.0.0.1:8000/",
        "sub": sub,
        "aud": "http://127.0.0.1:8000",
        "iat": now.timestamp(),
        "exp": (now + timedelta(hours=24)).timestamp(),
        "scope": "openid",
    }

    private_key_text = (Path(__file__).parent/'../../private_key.pem').read_text()
    private_key = serialization.load_pem_private_key(
        private_key_text.encode(),
        password=None,
    )
    return jwt.encode(payload=payload, key=private_key, algorithm="RS256")


# verify password using passlib
def verify_password(plain_password, hashed_password):
    return password_context.verify(plain_password, hashed_password)
