import redis
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import ConnectionFailure
import urllib

import os
from dotenv import load_dotenv
load_dotenv()

username= os.environ["username"] = os.getenv("username")
password = os.environ["password"] = os.getenv("password")
cluster_url = os.environ["cluster_url"] = os.getenv("cluster_url")
database_name = os.environ["database_name"] = os.getenv("database_name")

def redis_conn():
    return redis.Redis(host='localhost', port=6379, db=0)
    
username = urllib.parse.quote_plus(username)
password = urllib.parse.quote_plus(password)
MONGO_URI = f"mongodb+srv://{username}:{password}@{cluster_url}/{database_name}?retryWrites=true&w=majority"

client = AsyncIOMotorClient(MONGO_URI)
db = client.cyber
users_collection = db.users