#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
import json
import boto3
import logging
import os

from lambda_helper import (assemble_tx,
                           assemble_contract,
                           get_params,
                           get_tx_params,
                           get_contract_params,
                           calc_eth_address,
                           get_kms_public_key)

LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING")
LOG_FORMAT = "%(levelname)s:%(lineno)s:%(message)s"
handler = logging.StreamHandler()

_logger = logging.getLogger()
_logger.setLevel(LOG_LEVEL)

'''
Lambda関数実行時の引数によって、実行する処理の内容を変える
- status -> 所定のKMS IDの秘密鍵が持つウォレットアドレスを返す
- send -> 所定のKMS IDの秘密鍵を使用して、送金トランザクションを実行する
'''
def lambda_handler(event, context):
    _logger.debug("incoming event: {}".format(event))

    try:
        params = get_params()
    except Exception as e:
        raise e

    operation = event.get('operation')
    if not operation:
        raise ValueError('operation needs to be specified in request and needs to be eigher "status" or "send"')

    # {"operation": "status"}
    if operation == 'status':
        key_id = os.getenv('KMS_KEY_ID')
        pub_key = get_kms_public_key(key_id)
        eth_checksum_address = calc_eth_address(pub_key)

        return {'eth_checksum_address': eth_checksum_address}

    # 送金トランザクション ※引数のイメージは下記
    # {"operation": "send",
    #  "amount": 123,
    #  "dst_address": "0x...",
    #  "nonce": 0}
    elif operation == 'send':

        if not (event.get('dst_address') and event.get('amount', -1) >= 0 and event.get('nonce', -1) >= 0):
            return {
                'operation': 'sign',
                'error': 'missing parameter - sign requires amount, dst_address and nonce to be specified'
            }

        # Set Params from environment varaible
        key_id = os.getenv('KMS_KEY_ID')

        # Set Params from send request
        dst_address = event.get('dst_address')
        amount = event.get('amount')
        chainid = event.get('chainid')
        type = event.get('type')
        max_fee_per_gas = event.get('max_fee_per_gas')
        max_priority_fee_per_gas = event.get('max_priority_fee_per_gas')

        # download public key from KMS & calculate the Ethereum public address
        pub_key = get_kms_public_key(key_id)
        eth_checksum_addr = calc_eth_address(pub_key)

        # collect rawd parameters for Ethereum transaction
        tx_params = get_tx_params(dst_address=dst_address,
                                  amount=amount,
                                  eth_addr=eth_checksum_addr,
                                  chainid=chainid,
                                  type=type,
                                  max_fee_per_gas=max_fee_per_gas,
                                  max_priority_fee_per_gas=max_priority_fee_per_gas)

        # assemble Ethereum transaction and sign it offline
        raw_tx_signed_hash, raw_tx_signed_payload = assemble_tx(tx_params=tx_params,
                                                                params=params,
                                                                eth_checksum_addr=eth_checksum_addr,
                                                                chainid=chainid)

        return {
            'operation': 'sign',
            "signed_tx_hash": raw_tx_signed_hash,
            "signed_tx_payload": raw_tx_signed_payload
        }

    # ToDo：スマートコントラクトの実行
    elif operation == 'nft721':
        if not (event.get('max_fee_per_gas', -1) >= 0):
            return {
                'operation': 'nft721',
                'error': 'missing parameter - NFT721 requires max_fee_per_gas to be specified'
            }
        
        s3 = boto3.client('s3')
        
        # Set Params from environment varaible
        key_id = os.getenv('KMS_KEY_ID')

        # Get Contract JSON from S3
        s3_bucket = event.get('contract_json_bucket')
        s3_obj_key = event.get('contract_json_objkey')
        s3_res = s3.get_object(Bucket=s3_bucket, Key=s3_obj_key)
        contract_json = json.load(s3_res['Body'])

        # Set Params from send request
        dst_address = event.get('dst_address')
        chainid = event.get('chainid')
        type = event.get('type')
        gas = event.get('gas')
        max_fee_per_gas = event.get('max_fee_per_gas')
        max_priority_fee_per_gas = event.get('max_priority_fee_per_gas')
        contract_addr = event.get('contract_address')
        contract_func = event.get ('contract_function')
        contract_params = event.get('contract_params')

        # download public key from KMS & calculate the Ethereum public address
        pub_key = get_kms_public_key(key_id)
        eth_checksum_addr = calc_eth_address(pub_key)

        # collect rawd parameters for Ethereum transaction
        tx_params = get_contract_params(eth_addr=eth_checksum_addr,
                                  chainid=chainid,
                                  type=type,
                                  gas=gas,
                                  max_fee_per_gas=max_fee_per_gas,
                                  max_priority_fee_per_gas=max_priority_fee_per_gas)

        # assemble Ethereum transaction and sign it offline
        tx_hash = assemble_contract(tx_params=tx_params,
                                    params=params,
                                    contract_json=contract_json,
                                    contract_addr=contract_addr,
                                    contract_func=contract_func,
                                    contract_params=contract_params)

        return {
            'operation': 'nft721',
            "signed_tx_hash": tx_hash
        }

    # ToDO：BlockcertsによるVC発行
    elif operation == 'issuer':
        return {
            "message": "Hello, World!!"
        }