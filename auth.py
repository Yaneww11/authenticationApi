from base64 import b64decode

from datetime import datetime, timedelta
from typing import Annotated, Optional
from fastapi import Depends, HTTPException, APIRouter
from fastapi.params import Header
from sqlalchemy.orm import Session
from starlette import status
from database import SessionLocal
from models import User, Token, CreateUserRequest, TokenValidationResponse, TokenValidationRequest
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt, ExpiredSignatureError
from settings import settings
from uuid import uuid4

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)

# Secret key for signing the JWT
SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM
ACCESS_TOKEN_EXPIRE_SECONDS = settings.ACCESS_TOKEN_EXPIRE_SECONDS

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/token")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

@router.post("/generate_token", response_model=Token)
async def generate_access_token(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    if not authorization or not authorization.startswith("Basic "):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing authorization header",
            headers={"WWW-Authenticate": "Basic"},
        )
    try:
        credentials = b64decode(authorization.split(" ")[1]).decode("utf-8")
        client_id, client_secret = credentials.split(":", 1)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid credentials format")

    user = authenticate_user(client_id, client_secret, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(user.username, user.id, timedelta(seconds=ACCESS_TOKEN_EXPIRE_SECONDS))
    return {"access_token": token, "token_type": "Bearer", "expires_in": ACCESS_TOKEN_EXPIRE_SECONDS}

def create_access_token(username: str, user_id: int, expires_delta: timedelta):
    expires = datetime.utcnow() + expires_delta
    encode = {
        "sub": username,
        "id": user_id,
        "exp": expires,
        "iss": "tokens_staging_cardbox",  # Token issuer
        "aud": "microservices",  # Intended audience
        "iat": datetime.utcnow(), # issued at
        # Unique identifier for the token
        # I do not need it if system doesn't check for token uniqueness or revocation
        "jti": str(uuid4())
    }
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

def authenticate_user(username: str, password: str, db: Session):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.hashed_password):
        return False
    return user

def get_current_user(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing authorization header",
        headers={"WWW-Authenticate": "Bearer"},
    )

    token = authorization.split(" ")[1]
    payload = decode_jwt(token)

    username: str = payload.get("sub")
    user_id: int = payload.get("id")

    if username is None or user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid data",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.id == user_id, User.username == username).first()

    return user

user_dependency = Annotated[dict, Depends(get_current_user)]

@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(user: user_dependency,db: db_dependency, create_user_request: CreateUserRequest):
    if db.query(User).filter(User.username == create_user_request.username).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    create_user_model = User(
        username=create_user_request.username,
        hashed_password=bcrypt_context.hash(create_user_request.password),
    )

    db.add(create_user_model)
    db.commit()

    return {"username": create_user_model.username}

def decode_jwt(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            audience="microservices",  # Your service identifier
            issuer="tokens_staging_cardbox"  # Your auth service identifier
        )

        return payload
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired"
        )
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
        )

@router.post("/validate-token", response_model=TokenValidationResponse)
async def validate_token(request: TokenValidationRequest):
    try:
        token = request.token
        payload = decode_jwt(token)
        return {
            "is_valid": True,
            "details": {
                "username": payload.get("sub"),
                "user_id": payload.get("id"),
                "exp": payload.get("exp"),
                "iss": payload.get("iss")
            }
        }
    except HTTPException as e:
        return TokenValidationResponse(
            is_valid=False,
            error=str(e.detail)
        )