from pydantic import BaseModel, EmailStr, field_validator, Field
import re
from typing import Optional

class UserCreate(BaseModel):
    username: str
    password: str = Field(..., min_length=8)
    '''
    @field_validator('password')
    def validate_password(cls, value):
        if not re.search(r'[A-Z]', value):
            raise ValueError('Password must contain at least one uppercase letter.')
        if not re.search(r'[a-z]', value):
            raise ValueError('Password must contain at least one lowercase letter.')
        if not re.search(r'[0-9]', value):
            raise ValueError('Password must contain at least one digit.')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise ValueError('Password must contain at least one special character.')
        return value
        '''

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