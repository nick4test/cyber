from database import users_collection, redis_conn
import bcrypt
import hashlib
import uuid
from fastapi import HTTPException
from datetime import datetime, timedelta
from jose import jwt
import base64
import boto3
import json


async def get_user_by_username(username: str):
    user = await users_collection.find_one({"username": {"$eq": username}})
    return user


def get_ec2_instaces(aws_access_key: str,aws_secret_key: str,region_name: str):
    ec2 = boto3.client(
        'ec2',
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=region_name
    )
    response = ec2.describe_instances()
    instances_info = []
    for reservation in response.get('Reservations', []):
        for instance in reservation.get('Instances', []):
            instance_data = {
                "InstanceId": instance.get("InstanceId", "N/A"),
                "VpcId": instance.get("VpcId", "N/A"),
                "SecurityGroups": [
                    {
                        "GroupId": sg.get("GroupId", "N/A"),
                        "GroupName": sg.get("GroupName", "N/A")
                    } for sg in instance.get("SecurityGroups", [])
                ]
            }
            instances_info.append(instance_data)
    json_output = json.dumps(instances_info, indent=4)
    return json_output