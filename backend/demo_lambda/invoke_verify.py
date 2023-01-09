import boto3
import os
import json

function_name = os.getenv('FUNCTION_NAME')

def lambda_handler(event, context):
    print('[Invoke Verify Function] ??????')
    
    payload = {
        "address": "0xfadfa...",
        "jwt_token": "ey08fag..."
    }

    response = boto3.client('lambda').invoke(
        FunctionName = function_name,
        InvocationType='RequestResponse',
        Payload = payload
    )

    response_body = json.loads(response['Payload'].read())

    print(response_body)

    if response_body['status'] == "success":
        return {
            "status": "success",
            "detail": response_body
        }
    else:
        return {
            "status": "failed",
            "detail": response_body
        }