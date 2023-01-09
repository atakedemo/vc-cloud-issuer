#import json
import boto3
import logging
import os
import sys
import time
import json
import base64
from web3 import Web3, HTTPProvider
from eth_account.messages import encode_defunct

LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING")
LOG_FORMAT = "%(levelname)s:%(lineno)s:%(message)s"
handler = logging.StreamHandler()
_logger = logging.getLogger()
_logger.setLevel(LOG_LEVEL)

provider = os.getenv('ETH_PROVIDER')
key_id = os.getenv('KMS_KEY_ID')
w3 = Web3(HTTPProvider(provider))

session = boto3.session.Session()
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(lineno)d - %(message)s')
handler.setFormatter(formatter)

'''
クライアントから受け取ったデジタル署名について、
アドレス(≒公開鍵)と元のメッセージを使って検証する
問題なければ一時認証トークンを返す
'''
def lambda_handler(event, context):
    _logger.debug("incoming event: {}".format(event))
    event_body = event['body-json']

    # Set Params from send request
    #tgt_addr = event.get('tgt_addr')
    #message = event.get('message')
    #signature = event.get('signature')
    tgt_addr = event_body['tgt_addr']
    message = event_body['message']
    signature = event_body['signature']

    message_hash = encode_defunct(text=message)
    actual_addr = w3.eth.account.recover_message(message_hash, signature=signature)
    isVerified = actual_addr == tgt_addr

    if isVerified:
        jwt_token = create_jwt(actual_addr)
        return {
            'status': 'success',
            'address': actual_addr,
            'token': jwt_token
        }
    else:
        return {
            'status': 'failed',
            'error': 'Unautorization'
        }

def create_jwt(address:str) -> str:
    issued_at = int(time.time())
    expiration_time = issued_at + 3600
    header = {
        "alg": "RS256", 
        "typ": "JWT"
    }
    payload = {
        "iss": issued_at, 
        "exp": expiration_time,
        "wallet": {
            "address": address,
            "ENS": "none"
        }
    }

    token_components = {
        "header":  base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("="),
        "payload": base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("="),
    }
    message = json.dumps(token_components)
    kms_client = boto3.client("kms")
    signature: bytes = kms_client.sign(
        KeyId=key_id, 
        Message=message.encode(), 
        SigningAlgorithm="ECDSA_SHA_256",
        MessageType="RAW"
    )["Signature"]

    token_components["signature"] = base64.urlsafe_b64encode(signature).decode().rstrip("=")

    return f'{token_components["header"]}.{token_components["payload"]}.{token_components["signature"]}'