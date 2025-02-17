from typing import Optional
from pydantic import BaseModel
from database import Base
from sqlalchemy import Column, Integer, String

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class CreateUserRequest(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    expires_in: int
    token_type: str

class TokenValidationRequest(BaseModel):
    token: str

class TokenValidationResponse(BaseModel):
    is_valid: bool
    details: Optional[dict] = None
    error: Optional[str] = None