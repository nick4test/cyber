from fastapi import APIRouter, Depends, HTTPException, Header, Request, Form, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from jose import JWTError
import jwt
from user_registration import auth
from fastapi.templating import Jinja2Templates
from datetime import timedelta
import re
from typing import Optional
import boto3
import json
from cloud_scanners import crud


router = APIRouter()
@router.post("/ec2_instance", response_model=dict)
async def dashboard(
    request: Request,
    access_key: Optional[str] = Header(None, alias="accesskey"),  # Optionally provide access_key in header
    authorization: str = Header(..., alias="authorization"),
    aws_access_key: str = Header(..., alias="aws_access_key"),
    aws_secret_key: str = Header(..., alias="aws_secret_key"),   
    aws_region: str = Header(..., alias="aws_region"),   
    ):

    if access_key:
        user = await crud.get_user_by_access_key(access_key)
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired access key",
            )
        else:
            instances = crud.get_ec2_instaces(aws_access_key,aws_secret_key,aws_region)
            return JSONResponse(content={"instances": instances})
        
    # Authenticate using Authorization header
    elif authorization:
        token = authorization.split(" ")[1]   
        user = await auth.verify_token(token)
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired token",
            )
        else:
            instances = crud.get_ec2_instaces(aws_access_key,aws_secret_key,aws_region)
            return JSONResponse(content={"instances": instances})
        
    else:
        raise HTTPException(
            status_code=401,
            detail="Authorization or access key required",
        )