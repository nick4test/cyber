# routes.py
from fastapi import APIRouter, Depends, HTTPException, Header, Request, Form, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt
from fastapi.templating import Jinja2Templates
from . import schemas, crud, auth
from datetime import timedelta
import re
from typing import Optional

router = APIRouter()
templates = Jinja2Templates(directory="user_registration/templates")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
@router.get("/register", response_class=HTMLResponse)
async def register(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@router.post("/register", response_class=HTMLResponse)
async def register_user(request: Request, email: str = Form(...), password: str = Form(...)):
    email_pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
   
    if not re.match(email_pattern, email):
        raise HTTPException(status_code=400, detail="Please provide a valid email address")
    
    user = schemas.UserCreate(username=email, password=password)
    db_user = await crud.get_user_by_username(user.username)

    accept_header = request.headers.get("Accept", " ")
    
    if "text/html" in accept_header:
        if db_user:
            return JSONResponse(status_code=400, content={"error": "Username already registered"})  
        await crud.create_user(user)
        return JSONResponse(status_code=200, content={"success": "User registered successfully"})
    else:
        if db_user:
            return templates.TemplateResponse("register.html", {"request": request, "error": "Username already registered"})
        await crud.create_user(user)
        return templates.TemplateResponse("register.html", {"request": request, "success": "User registered successfully"})  

@router.get("/login", response_class=HTMLResponse)
async def login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@router.post("/token", response_model=schemas.Token)
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    user = await crud.verify_password(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"data":{"sub": form_data.username, "Admin": "no", "dt_type": ["string"]}}, expires_delta=access_token_expires
    )
    refresh_token_expires = timedelta(minutes=auth.REFRESH_TOKEN_EXPIRE_MINUTES)
    refresh_token = auth.create_refresh_token(
        data={"sub": form_data.username}, expires_delta=refresh_token_expires
    )

    accept_header = request.headers.get("accept", "")
    if "application/json" in accept_header:
        return {
            "token_type": "bearer",
            "access_token": access_token,
            "refresh_token": refresh_token,
        }
    else:
        response = RedirectResponse(url="http://127.0.0.1:8000/dashboard", status_code=302)
        response.headers["Authorization"] = f"Bearer {access_token}"
        response.headers["X-Refresh-Token"] = refresh_token
        response.headers["Referer"] = "http://127.0.0.1:8000/dashboard"
        return response

@router.post("/refresh", response_model=dict)
async def refresh_access_token(refresh_token: str = Header(None, alias="refresh_token")):
    payload = auth.verify_refresh_token(refresh_token, auth.SECRET_KEY)
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
    access_token = auth.create_access_token(
        data={"sub": username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

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


'''

if you want the request routed from main file to user_registration/routes.py to /cloud_scanners 
(for example http://127.0.0.1/user_registration/cloud_scanners/ec2_instance)
from cloud_scanners import routes as cloud_scanner
router.include_router(cloud_scanner.router, prefix="/cloud_scanners") 

'''