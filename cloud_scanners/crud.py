import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError    
from fastapi import HTTPException
from .schemas import AWSCredentials



async def check_aws_connection(awscreds: AWSCredentials):
    try:
        # Create a session using the provided credentials
        session = boto3.Session(
            aws_access_key_id=awscreds.aws_access_key,
            aws_secret_access_key=awscreds.aws_secret_key,
            region_name=awscreds.aws_region
        )
            # Create an S3 client
        s3_client = session.client('s3')

        # List buckets to check connectivity
        s3_client.list_buckets()
        return {"message": "Successfully connected to AWS"}
    except NoCredentialsError:
        raise HTTPException(status_code=400, detail="Credentials not available")
    except PartialCredentialsError:
        raise HTTPException(status_code=400, detail="Incomplete credentials provided")
    except ClientError as e:
        raise HTTPException(status_code=400, detail=f"AWS Client Error: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {e}")

    


async def ec2_scans(awscreds: AWSCredentials):
    try:
        session = boto3.Session(
            aws_access_key_id=awscreds.aws_access_key,
            aws_secret_access_key=awscreds.aws_secret_key,
            region_name=awscreds.aws_region,
        )   
        ec2_client = session.client('ec2')
        iam_client = session.client('iam')

        # Describe EC2 instances
        response = ec2_client.describe_instances()
        instances = []

        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                iam_role = instance.get('IamInstanceProfile', {}).get('Arn', 'No IAM Role')

                # Get IAM role policies
                if iam_role:
                    role_name = iam_role.split('/')[-1]
                    policies = iam_client.list_attached_role_policies(RoleName=role_name)
                    policy_names = [policy['PolicyName'] for policy in policies['AttachedPolicies']]
                else:
                    policy_names = []

                instances.append({
                    'instance_id': instance_id,
                    'iam_role': iam_role,
                    'permissions': policy_names
                })
        return instances
    except (NoCredentialsError, PartialCredentialsError):
        raise HTTPException(status_code=400, detail="Invalid AWS credentials")
    except ClientError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))