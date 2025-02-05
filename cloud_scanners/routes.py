from typing import Optional 
from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import  JSONResponse
from user_registration import auth , crud as user_crud
from cloud_scanners import crud
from .schemas import AWSCredentials  


router = APIRouter()    


@router.post("/check_aws_connectivity/")
async def AWS_ec2_scan(
        access_key: Optional[str] = Header(None, alias="access_key"),  # Optionally provide access_key in header
        authorization: Optional[str] = Header(None, alias="authorization"),
        aws_access_key: Optional[str] = Header(None, alias="aws_access_key"),  # Optionally provide AWS access key
        aws_secret_key: Optional[str] = Header(None, alias="aws_secret_key"),  # Optionally provide AWS secret key
        aws_region: Optional[str] = Header(None, alias="aws_region")  # Optionally provide AWS region
        ):
    
    if access_key:
        user = await user_crud.get_user_by_access_key(access_key)
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired access key",
            )
        if not aws_access_key or not aws_secret_key or not aws_region:
            raise HTTPException(status_code=400, detail="AWS access key, secret key and region required")
        return JSONResponse(await crud.check_aws_connection(AWSCredentials(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key, aws_region=aws_region)))
    elif authorization:
        token = authorization.split(" ")[1]   
        user = await auth.verify_token(token)
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired token",
            )
        if not aws_access_key or not aws_secret_key or not aws_region:
            raise HTTPException(status_code=400, detail="AWS access key, secret key and region required")
        return JSONResponse(await crud.check_aws_connection(AWSCredentials(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key, aws_region=aws_region)))
    else:
        raise HTTPException(
            status_code=401,
            detail="Authorization or access key required",
        )


@router.post("/AWS_ec2_scan", response_class=JSONResponse)
async def AWS_ec2_scan(
    access_key: Optional[str] = Header(None, alias="access_key"),  # Optionally provide access_key in header
    authorization: Optional[str] = Header(None, alias="authorization"),
    aws_access_key: Optional[str] = Header(None, alias="aws_access_key"),  # Optionally provide AWS access key
    aws_secret_key: Optional[str] = Header(None, alias="aws_secret_key"),  # Optionally provide AWS secret key
    aws_region: Optional[str] = Header(None, alias="aws_region")  # Optionally provide AWS region
    ):

    if access_key:
        user = await user_crud.get_user_by_access_key(access_key)
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired access key",
            )
        if not aws_access_key or not aws_secret_key or not aws_region:
            raise HTTPException(status_code=400, detail="AWS access key, secret key and region required")
        return JSONResponse(await crud.ec2_scans(AWSCredentials(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key, aws_region=aws_region)))
    elif authorization:
        token = authorization.split(" ")[1]   
        user = await auth.verify_token(token)
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired token",
            )
        if not aws_access_key or not aws_secret_key or not aws_region:
            raise HTTPException(status_code=400, detail="AWS access key, secret key and region required")
        return JSONResponse(await crud.ec2_scans(AWSCredentials(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key, aws_region=aws_region)))
    else:
        raise HTTPException(
            status_code=401,
            detail="Authorization or access key required",
        )