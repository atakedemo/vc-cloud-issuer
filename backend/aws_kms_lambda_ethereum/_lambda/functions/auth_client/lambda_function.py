#import json
import boto3
import logging
import os
import sys
from web3 import Web3, HTTPProvider
from eth_account.messages import encode_defunct

LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING")
LOG_FORMAT = "%(levelname)s:%(lineno)s:%(message)s"
handler = logging.StreamHandler()
_logger = logging.getLogger()
_logger.setLevel(LOG_LEVEL)

provider = os.getenv('ETH_PROVIDER')
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


    if not (event.get('tgt_addr')):
        return {
            'error': 'missing parameter - sign requires amount, dst_address and nonce to be specified'
        }
    
    # Set Params from send request
    tgt_addr = event.get('tgt_addr')
    message = event.get('message')
    signature = event.get('signature')

    message_hash = encode_defunct(text=message)
    #actual_addr = w3.eth.account.recoverHash(message_hash, signature=signature)
    actual_addr = w3.eth.account.recover_message(message_hash, signature=signature)
    isVerified = actual_addr == tgt_addr

    if isVerified:
        return {
            'address': actual_addr,
            'token': 'eyJ0e...'
        }
    else:
        return {
            'error': 'Unautorization'
        }