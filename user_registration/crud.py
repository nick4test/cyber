# crud.py
from .database import users_collection, redis_conn
import bcrypt
import hashlib
import uuid
from fastapi import HTTPException
from datetime import datetime, timedelta
from jose import jwt
import base64
from .schemas import UserCreate
from .auth import SECRET_KEY, ALGORITHM 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

import os
from dotenv import load_dotenv
load_dotenv()
key= os.environ["key"] = os.getenv("key")
key = key.encode('utf-8')[:32]
encryption_key = base64.urlsafe_b64encode(key).decode('utf-8')

redis_client = redis_conn()   

async def get_user_by_username(username: str):
    """
    Retrieve a user by their username from MongoDB.
    """
    user = await users_collection.find_one({"username": {"$eq": username}})
    return user

async def create_user(user: UserCreate):
    """
    Create a new user in MongoDB with a hashed password.
    """
    # Preprocess the password with SHA-256
    sha256_password = hashlib.sha256(user.password.encode('utf-8')).hexdigest()
   
    # Hash the SHA-256 processed password using bcrypt
    hashed_password = bcrypt.hashpw(sha256_password.encode('utf-8'), bcrypt.gensalt())

    # Generate a unique user ID
    unique_user_id = str(uuid.uuid4())
    
    # Create the new user object
    user_data = {
        "_id": unique_user_id,
        "username": user.username,
        "hashed_password": hashed_password.decode('utf-8'),
        "user_id": unique_user_id,
        "role": ["user, admin"],
    }
    
    # Insert the user into the MongoDB collection
    result = await users_collection.insert_one(user_data)
    return user_data

async def verify_password(username: str, password: str):
    """
    Verify a user's password.
    """
    user = await get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Preprocess the input password with SHA-256
    sha256_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    # Verify the bcrypt hash
    if bcrypt.checkpw(sha256_password.encode('utf-8'), user["hashed_password"].encode('utf-8')):
        return True
    return False

def encrypt_access_key(plain_text: str) -> str:
    """
    Encrypt an access key using AES encryption.
    """
    iv = b'd\xec;bNr\x0b\xdd\x92\xe9\xed\x8aV\x9b\x86X'
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plain_text.encode('utf-8')) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv + encrypted_data).decode('utf-8')

def decrypt_access_key(encrypted_text: str) -> str:
    """
    Decrypt an encrypted access key using AES decryption.
    """
    encrypted_data = base64.urlsafe_b64decode(encrypted_text)
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data.decode('utf-8')

async def create_access_key(username: str):
    """
    Generate and store an access key for a user.
    """
    user = await get_user_by_username(username)
    if user:
        # Generate a JWT token
        token_payload = {
            'sub': username,
            'iat': datetime.now(),
            'exp': datetime.now() + timedelta(days=180)  # Token expiration time
        }
        token = jwt.encode(token_payload, encryption_key, algorithm='HS256')

        # Encrypt the JWT token using AES
        encrypted_key = encrypt_access_key(token)
        
        # Update the user's access key in the database
        await users_collection.update_one({"username": username}, {"$set": {"access_key": encrypted_key}})
        return encrypted_key
    return None

async def delete_access_key(username: str):
    """
    Delete a user's access key.
    """
    user = await get_user_by_username(username)
    if user:
        await users_collection.update_one({"username": username}, {"$set": {"access_key": None}})
        return True
    return False

async def get_user_by_access_key(access_key: str):
    """
    Retrieve a user by their access key.
    """
    try:
        decrypted_key = decrypt_access_key(access_key)
    except Exception as e:
        return None

    try:
        payload = jwt.decode(decrypted_key, encryption_key, algorithms=['HS256'])
        username = payload.get('sub')
        user = await get_user_by_username(username)
        return user
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

async def add_token_to_blacklist(token: str, refresh_token: str):
    """
    Add a token and refresh token to the blacklist in Redis.
    """
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    username: str = payload.get("data").get("sub")
    redis_client.hset(token, mapping={"status": "blacklisted", "username": username})
    redis_client.expire(token, 1800)
    redis_client.hset(refresh_token, mapping={"status": "blacklisted", "username": username})
    redis_client.expire(refresh_token, 1800)

async def is_token_blacklisted(token: str) -> bool:
    """
    Check if a token is blacklisted in Redis.
    """
    return redis_client.exists(token)

async def revoke_access_key(access_key: str):
    redis_client.hset(access_key, mapping={"status": "blacklisted"})
    redis_client.expire(access_key, 17280000)  # 200 days