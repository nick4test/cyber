from pydantic import BaseModel, EmailStr, field_validator, Field
import re
from typing import Optional

class User(BaseModel):
    id: int
    username: str
    access_key: str
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str

class TokenData(BaseModel):
    username: Optional[str] = None

class AccessKey(BaseModel):
    access_key: str