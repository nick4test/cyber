from pydantic import BaseModel, EmailStr, field_validator, Field
import bleach
import re
from typing import Optional

class UserCreate(BaseModel):
    username: str = EmailStr
    password: str = Field(..., min_length=8)
    
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

class XSSValidator(BaseModel):
    @staticmethod
    def validate_no_xss(value: str) -> str:
        xss_patterns = [
            r'<script.*?>.*?</script.*?>',
            r'javascript:',
            r'vbscript:',
            r'on\w+=',
            r'&#\d+;',
            r'&\w+;',
        ]
        for pattern in xss_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValueError('Potential XSS detected.')
        return value
    
class UserInput(BaseModel):
    value: str
    @field_validator('value')
    def check_for_xss(cls, value):
        # Sanitize the input to remove any potential XSS
        cleaned_value = bleach.clean(value)
        if cleaned_value != value:
            raise ValueError('Potential XSS detected')
        return cleaned_value
    
class LoginRequest(BaseModel):
    username: str
    password: str

class accountdetails(BaseModel):
    first_name: str
    last_name: str  

