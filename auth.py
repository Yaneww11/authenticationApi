from datetime import datetime, timedelta
from typing import Annotated
from fastapi import Depends, HTTPException, APIRouter
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status
from database import SessionLocal
from models import User
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)

# Secret key for signing the JWT
SECRET_KEY = "7ed1d879c78eac55ec29bbd5ff79088454acb9bfe518f144f704aa7450dae28e79f3826764b9ca6af3a110356879cb72ad3ab739493b29436dc5a76604d52dd3"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 20

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

@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependency, create_user_request: CreateUserRequest):
    create_user_model = User(
        username=create_user_request.username,
        hashed_password=bcrypt_context.hash(create_user_request.password),
    )

    db.add(create_user_model)
    db.commit()


def create_access_token(username: str, user_id: int, expires_delta: timedelta):
    expires = datetime.utcnow() + expires_delta
    encode = {
        "sub": username,
        "id": user_id,
        "exp": expires
    }
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(user.username, user.id, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": token, "token_type": "bearer", "expire_minutes": ACCESS_TOKEN_EXPIRE_MINUTES}

def authenticate_user(username: str, password: str, db: Session):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.hashed_password):
        return False
    return user