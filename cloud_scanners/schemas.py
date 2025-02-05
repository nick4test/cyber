
from pydantic import BaseModel

class AWSCredentials(BaseModel):
    aws_access_key: str
    aws_secret_key: str
    aws_region: str 

