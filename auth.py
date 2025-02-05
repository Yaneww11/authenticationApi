from datetime import datetime, timedelta
from typing import Annotated, Optional
from fastapi import Depends, HTTPException, APIRouter
from fastapi.params import Header
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status
from database import SessionLocal
from models import User
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from settings import settings

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)

# Secret key for signing the JWT
SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/token")

class CreateUserRequest(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    expire_minutes: int

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

@router.post("/token", response_model=Token)
async def login_for_access_token(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    if not authorization or not authorization.startswith("Basic "):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing authorization header",
            headers={"WWW-Authenticate": "Basic"},
        )

    import base64
    try:
        credentials = base64.b64decode(authorization.split(" ")[1]).decode("utf-8")
        client_id, client_secret = credentials.split(":", 1)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid credentials format")

    # Validate user
    user = authenticate_user(client_id, client_secret, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Generate Token
    token = create_access_token(user.username, user.id, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))

    return {"access_token": token, "token_type": "bearer", "expire_minutes": ACCESS_TOKEN_EXPIRE_MINUTES}


def create_access_token(username: str, user_id: int, expires_delta: timedelta):
    expires = datetime.utcnow() + expires_delta
    encode = {
        "sub": username,
        "id": user_id,
        "exp": expires
    }
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


def authenticate_user(username: str, password: str, db: Session):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.hashed_password):
        return False
    return user

async def get_current_user(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not authorization or not authorization.startswith("Bearer "):
        raise credentials_exception

    try:
        token = authorization.split(" ")[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("id")

        if username is None or user_id is None:
            raise credentials_exception

        user = db.query(User).filter(User.id == user_id, User.username == username).first()
        if not user:
            raise credentials_exception

        return user
    except JWTError:
        raise credentials_exception

user_dependency = Annotated[dict, Depends(get_current_user)]

@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(user: user_dependency,db: db_dependency, create_user_request: CreateUserRequest):
    create_user_model = User(
        username=create_user_request.username,
        hashed_password=bcrypt_context.hash(create_user_request.password),
    )

    db.add(create_user_model)
    db.commit()