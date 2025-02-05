# routes.py
from fastapi import APIRouter, Depends, HTTPException, Header, Request,Response, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer 
import jwt
from fastapi.templating import Jinja2Templates
from . import schemas, crud, auth
from datetime import timedelta
import re
from typing import Optional
from .schemas import LoginRequest
import main

router = APIRouter()
templates = Jinja2Templates(directory="user_registration/templates")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@router.get("/register", response_class=HTMLResponse)
async def register(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@router.post("/register", response_class=JSONResponse)
async def register_user(request: Request, user_create: schemas.UserCreate):
    email_pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
   
    if not re.match(email_pattern, user_create.username):
        raise HTTPException(status_code=400, detail="Please provide a valid email address")
    
    user = schemas.UserCreate(username=user_create.username, password=user_create.password)
    db_user = await crud.get_user_by_username(user.username)
    if db_user:
        return JSONResponse(status_code=400, content={"error": "Username already registered"})  
    await crud.create_user(user)
    return JSONResponse(status_code=200, content={"success": "User registered successfully"})
   
@router.get("/login", response_class=HTMLResponse)
async def login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@router.post("/token", response_model=schemas.Token)
async def login_for_access_token(request: Request, Login_data: LoginRequest):
    user = await crud.verify_password(Login_data.username, Login_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = await auth.create_access_token(
        data={"data":{"sub": Login_data.username, "Admin": "no", "dt_type": ["string"]}}, expires_delta=access_token_expires
    )
    refresh_token_expires = timedelta(minutes=auth.REFRESH_TOKEN_EXPIRE_MINUTES)
    refresh_token = await auth.create_refresh_token(
        data={"sub": Login_data.username}, expires_delta=refresh_token_expires
    )
    response= {
            "token_type": "bearer",
            "access_token": access_token,
            "refresh_token": refresh_token,
        }
    return response

@router.post("/refresh", response_model=schemas.Token)
async def refresh_access_token(refresh_token: str = Header(None, alias="refresh_token")):
    payload = await auth.verify_refresh_token(refresh_token, auth.SECRET_KEY)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    username: str = payload.get("sub") 

    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = await auth.create_access_token(
        data={"sub": username}, expires_delta=access_token_expires
    )
    return JSONResponse({"access_token": access_token, "token_type": "bearer"})

@router.post("/access_key", response_model=schemas.AccessKey)
async def access_key(
    request: Request,
    authorization: str = Header(None),  # Fetch token from the Authorization header
    ):
   
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Token not provided or invalid format",
        )
    
    token = authorization.split(" ")[1]
    user = await auth.verify_token(token)
    if not user:
        raise HTTPException(
                status_code=401,
                detail="Invalid or expired token",
        )
    access_key = await crud.create_access_key(user["username"])
    return JSONResponse(content={"access_key": access_key, "warning": "Please save this access key and store it securely as it will not be shown again"})

@router.post("/access_key_delete", response_model=schemas.AccessKey)
async def access_key(
    request: Request,
    authorization: str = Header(...,description="Authorization header is required", alias="authorization"),
    access_key: str = Header(None,alias="accesskey"),  # Fetch token from the Authorization header
    ):   

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Token not provided or invalid format",
        )
    
    authorization = authorization.split(" ")[1]
    user = await auth.verify_token(authorization)
    if not user:
        raise HTTPException(
            status_code=401,    
            detail="Invalid or expired token",
        )
    if authorization:
       await crud.revoke_access_key(access_key)
       return JSONResponse(status_code=200, content={"Succes": "Deleted"})


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    access_key: Optional[str] = Header(None, alias="accesskey"),  # Optionally provide access_key in header
    authorization: Optional[str] = Header(None, alias="authorization"),
      # Optionally provide Authorization header
    ):

    if access_key:

        user = await crud.get_user_by_access_key(access_key)
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired access key",
            )
        return templates.TemplateResponse("dashboard.html", {"request": request, "username": user["username"]})
    # Authenticate using Authorization header
    elif authorization:
        token = authorization.split(" ")[1]   
        user = await auth.verify_token(token)
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired token",
            )
        return templates.TemplateResponse("dashboard.html", {"request": request, "username": user["username"]})
        
    else:
        raise HTTPException(
            status_code=401,
            detail="Authorization or access key required",
        )
@router.post("/logout")
async def logout(request: Request, token: str = Depends(oauth2_scheme),
           refresh_token :str = Header(None , alias="refresh_token")):
    await crud.add_token_to_blacklist(token, refresh_token)
    return {"detail": "Successfully logged out"}

@router.options("/preflight")
async def preflight(request: Request):  
    return Response(status_code=200, headers={
        "Access-Control-Allow-Methods": ", ".join(main.methods),
        "Access-Control-Allow-Headers": ", ".join(main.cors_headers)
    })

'''
if you want the request routed from main file to user_registration/routes.py to /cloud_scanners 
(for example http://127.0.0.1/user_registration/cloud_scanners/ec2_instance)
from cloud_scanners import routes as cloud_scanner
router.include_router(cloud_scanner.router, prefix="/cloud_scanners") 
'''

@router.post("/AccountDelete", response_class=JSONResponse)
async def account_delete(
    request: Request,
    access_key: Optional[str] = Header(None, alias="accesskey"),  # Optionally provide access_key in header
    authorization: Optional[str] = Header(None, alias="authorization"),
):
    if access_key:
        user = await crud.get_user_by_access_key(access_key)
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired access key",
            )
        await crud.delete_user_account(user["username"])
        return JSONResponse(status_code=200, content={"Success": "Account successfully deleted"})
    elif authorization:
        token = authorization.split(" ")[1]
        user = await auth.verify_token(token)
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired token",
            )
        await crud.delete_user_account(user["username"])
        return JSONResponse(status_code=200, content={"Success": "Account successfully deleted"})
    else:
        raise HTTPException(
            status_code=401,
            detail="Authorization or access key required",
        )

@router.post("/AccountUpdate", response_class=JSONResponse)
async def account_update(
    request: Request,
    details: schemas.accountdetails,
    access_key: Optional[str] = Header(None, alias="accesskey"),  # Optionally provide access_key in header
    authorization: Optional[str] = Header(None, alias="authorization"),
):
    if access_key:
        user = await crud.get_user_by_access_key(access_key)
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired access key",
            )
        try:
            validated_first_name = schemas.UserInput.check_for_xss(details.first_name)
            validated_last_name = schemas.UserInput.check_for_xss(details.last_name)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        await crud.add_first_last_name(user["username"], validated_first_name, validated_last_name)
        return JSONResponse(status_code=200, content={"Success": "Account successfully updated"})
    elif authorization:
        token = authorization.split(" ")[1]
        user = await auth.verify_token(token)
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired token",
            )
        try:
            validated_first_name = schemas.UserInput.check_for_xss(details.first_name)
            validated_last_name = schemas.UserInput.check_for_xss(details.last_name)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        await crud.add_first_last_name(user["username"], validated_first_name, validated_last_name)
        return JSONResponse(status_code=200, content={"Success": "Account successfully updated"})
    else:
        raise HTTPException(
            status_code=401,
            detail="Authorization or access key required",
        )

@router.post("/VerifyToken", response_class=JSONResponse)
async def verify_token(
    request: Request,
    authorization: Optional[str] = Header(None, alias="authorization"),
):
    if authorization:
        token = authorization.split(" ")[1]
        user = await auth.verify_token(token)
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Token is invalid or expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return JSONResponse(status_code=200, content={"Success": "Token is valid"})
    else:
        raise HTTPException(
            status_code=401,
            detail="Authorization token required",
        )

@router.post("/VerifyRefreshToken", response_class=JSONResponse)
async def verify_refresh_token(
    request: Request,
    refresh_token: Optional[str] = Header(None, alias="refresh_token"),
):
    if refresh_token:
        payload = await auth.verify_refresh_token(refresh_token, auth.SECRET_KEY)
        if payload is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return JSONResponse(status_code=200, content={"Success": "Refresh token is valid"})
    else:
        raise HTTPException(
            status_code=401,
            detail="Authorization token required",
        )