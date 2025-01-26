from fastapi import FastAPI, Request
from user_registration.routes import router
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from user_registration import crud
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from user_registration import routes as user_registration_routes
from cloud_scanners import routes as cloud_scanner


app = FastAPI()
app.mount("/static", StaticFiles(directory="user_registration/static"), name="static")
app.include_router(router)

# CORS configuration
methods = ["GET", "POST", "OPTIONS"]
cors_headers = ["Content-Type", "Referer", "Authorization", "Access-Control-Request-Method","aws_access_key", "aws_secret_key", "region_name","Access-Control-Request-Headers"]
origin = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origin,  # Allow all origins
    allow_credentials=True,
    allow_methods=methods,
    allow_headers=cors_headers,
    expose_headers=cors_headers,

)

# Middleware to set X-Frame-Options header
class XFrameOptionsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers['X-Frame-Options'] = 'SameOrigin'
        return response

app.add_middleware(XFrameOptionsMiddleware)

# Middleware to check if tokens are blacklisted
@app.middleware("http")
async def check_blacklist(request: Request, call_next):
    token = request.headers.get("Authorization")
    refresh_token = request.headers.get("refresh_token")
    access_key = request.headers.get("accesskey")

    if token:
        token = token.split(" ")[1]
        if await crud.is_token_blacklisted(token):  # Use await for async function
            return HTMLResponse(status_code=401, content="Token has been revoked")
        response = await call_next(request)
        return response

    if refresh_token:
        if await crud.is_token_blacklisted(refresh_token):  # Use await for async function
            return HTMLResponse(status_code=401, content="Token has been revoked")
        response = await call_next(request)
        return response

    if access_key:
        if await crud.is_token_blacklisted(access_key):  # Use await for async function
            return HTMLResponse(status_code=401, content="Token has been revoked")
        response = await call_next(request)
        return response

    response = await call_next(request)
    return response


app.include_router(cloud_scanner.router, prefix="/cloud_scanners")