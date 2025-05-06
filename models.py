from pydantic import BaseModel
from typing import Optional


class User(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str


class TokenData(BaseModel):
    username: Optional[str] = None
