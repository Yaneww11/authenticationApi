from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_SECONDS: int

    class Config:
        env_file = ".env"

# Create an instance
settings = Settings()
