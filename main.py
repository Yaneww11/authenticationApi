from fastapi import FastAPI, HTTPException, Depends
from datetime import datetime, timedelta
import jwt
from typing import Optional, Annotated
from sqlalchemy.orm import Session
from starlette import status

import auth
from database import SessionLocal, Base, engine
from models import User

app = FastAPI()
app.include_router(auth.router)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

# @app.get("/oauth2/token")
# async def generate_token(data: TokenData):
#     token = create_jwt_token({"sub": data.username}, timedelta(minutes=data.expires_in))
#     return {"access_token": token, "token_type": "bearer"}

# @app.post("/users/", response_model=UserResponse)
# def create_user(user: UserCreate, db: db_dependency):
#     db_user = User(username=user.username, password=user.password)
#     db.add(db_user)
#     db.commit()
#     db.refresh(db_user)
#     return db_user


@app.get("/", status_code=status.HTTP_200_OK)
async def user(user: None, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=400, detail="User not found")
    return {"user": user}