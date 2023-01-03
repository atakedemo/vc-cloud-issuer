#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import logging
import os
import sys

import asn1tools
import boto3
from ethereum_kms_signer import sign_transaction
from eth_account import Account
from eth_account._utils.signing import (
    encode_transaction, serializable_unsigned_transaction_from_dict)
#from web3.auto import w3
from web3 import Web3, HTTPProvider
from web3.contract import ConciseContract
provider = os.getenv('ETH_PROVIDER')
w3 = Web3(HTTPProvider(provider))

session = boto3.session.Session()
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(lineno)d - %(message)s')
handler.setFormatter(formatter)

_logger = logging.getLogger('app')
_logger.setLevel(os.getenv('LOGGING_LEVEL', 'WARNING'))
_logger.addHandler(handler)

# max value on curve / https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md
SECP256_K1_N = int("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)


class EthKmsParams:

    def __init__(self, kms_key_id: str, eth_network: str):
        self._kms_key_id = kms_key_id
        self._eth_network = eth_network

    def get_kms_key_id(self) -> str:
        return self._kms_key_id


def get_params() -> EthKmsParams:
    for param in ['KMS_KEY_ID', 'ETH_NETWORK']:
        value = os.getenv(param)

        if not value:
            if param in ['ETH_NETWORK']:
                continue
            else:
                raise ValueError('missing value for parameter: {}'.format(param))

    return EthKmsParams(
        kms_key_id=os.getenv('KMS_KEY_ID'),
        eth_network=os.getenv('ETH_NETWORK')
    )


def get_kms_public_key(key_id: str) -> bytes:
    client = boto3.client('kms')

    response = client.get_public_key(
        KeyId=key_id
    )

    return response['PublicKey']


def sign_kms(key_id: str, msg_hash: bytes) -> dict:
    client = boto3.client('kms')

    response = client.sign(
        KeyId=key_id,
        Message=msg_hash,
        MessageType='DIGEST',
        SigningAlgorithm='ECDSA_SHA_256'
    )

    return response


def calc_eth_address(pub_key) -> str:
    SUBJECT_ASN = '''
    Key DEFINITIONS ::= BEGIN

    SubjectPublicKeyInfo  ::=  SEQUENCE  {
       algorithm         AlgorithmIdentifier,
       subjectPublicKey  BIT STRING
     }

    AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm   OBJECT IDENTIFIER,
        parameters  ANY DEFINED BY algorithm OPTIONAL
      }

    END
    '''

    key = asn1tools.compile_string(SUBJECT_ASN)
    key_decoded = key.decode('SubjectPublicKeyInfo', pub_key)

    pub_key_raw = key_decoded['subjectPublicKey'][0]
    pub_key = pub_key_raw[1:len(pub_key_raw)]

    # https://www.oreilly.com/library/view/mastering-ethereum/9781491971932/ch04.html
    hex_address = w3.keccak(bytes(pub_key)).hex()
    eth_address = '0x{}'.format(hex_address[-40:])

    eth_checksum_addr = w3.toChecksumAddress(eth_address)

    return eth_checksum_addr


def find_eth_signature(params: EthKmsParams, plaintext: bytes) -> dict:
    SIGNATURE_ASN = '''
    Signature DEFINITIONS ::= BEGIN

    Ecdsa-Sig-Value  ::=  SEQUENCE  {
           r     INTEGER,
           s     INTEGER  }

    END
    '''
    signature_schema = asn1tools.compile_string(SIGNATURE_ASN)

    signature = sign_kms(params.get_kms_key_id(), plaintext)
    print("KMS signature ↓↓↓↓↓↓↓:")
    print(signature)
    # https://tools.ietf.org/html/rfc3279#section-2.2.3
    signature_decoded = signature_schema.decode('Ecdsa-Sig-Value', signature['Signature'])
    s = signature_decoded['s']
    r = signature_decoded['r']

    secp256_k1_n_half = SECP256_K1_N / 2

    if s > secp256_k1_n_half:
        s = SECP256_K1_N - s

    return {'r': r, 's': s}


def get_recovery_id(msg_hash, r, s, eth_checksum_addr, chainid) -> dict:
    # デジタル署名の vを計算する(EIP155) ※https://eips.ethereum.org/EIPS/eip-155
    # {0,1} + CHAIN_ID * 2 + 35
    v_lower = chainid * 2 + 35
    v_range = [v_lower, v_lower + 1]
    for v in v_range:
        recovered_addr = Account.recoverHash(message_hash=msg_hash, vrs=(v, r, s))
        if recovered_addr == eth_checksum_addr:
            return {"recovered_addr": recovered_addr, "y_parity": v - v_lower}
    return {}

def get_tx_params(dst_address: str, 
                  amount: int, 
                  eth_addr: str,
                  chainid: int, 
                  type: int, 
                  gas: int,
                  max_fee_per_gas: int, 
                  max_priority_fee_per_gas: int) -> dict:
    
    nonce = w3.eth.getTransactionCount(eth_addr)
    transaction = {
        'nonce': nonce,
        'to': dst_address,
        'value': w3.toWei(amount, 'ether'),
        'data': '0x00',
        'maxFeePerGas': max_fee_per_gas,
        'maxPriorityFeePerGas': max_priority_fee_per_gas,
        'type': type,
        'chainId': chainid,
    }
    return transaction

def get_contract_params(eth_addr: str,
                        chainid: int, 
                        type: int, 
                        gas: int,
                        max_fee_per_gas: int, 
                        max_priority_fee_per_gas: int) -> dict:
    nonce = w3.eth.getTransactionCount(eth_addr)
    transaction = {
        'nonce': nonce,
        'gas': gas,
        'maxFeePerGas': max_fee_per_gas,
        'maxPriorityFeePerGas': max_priority_fee_per_gas,
        'type': type,
        'chainId': chainid,
    }

    return transaction


def assemble_tx(tx_params: dict, 
                params: EthKmsParams, 
                eth_checksum_addr: str, 
                chainid: int) -> (bytes, bytes):
    tx_unsigned = serializable_unsigned_transaction_from_dict(transaction_dict=tx_params)
    tx_hash = tx_unsigned.hash()

    #渡されたtx_paramsではdataが仮の値のため、署名した値を代入する
    #tx_sig : KMSで作成したデジタル署名のr, s
    tx_sig = find_eth_signature(params=params,plaintext=tx_hash)
    tx_eth_recovered_pub_addr = get_recovery_id(msg_hash=tx_hash,
                                                r=tx_sig['r'],
                                                s=tx_sig['s'],
                                                eth_checksum_addr=eth_checksum_addr,
                                                chainid=chainid)
    tx_encoded = encode_transaction(unsigned_transaction=tx_unsigned,
                                    vrs=(
                                        tx_eth_recovered_pub_addr['y_parity'], 
                                        tx_sig['r'], 
                                        tx_sig['s']
                                    ))
    tx_params['data'] = tx_encoded

    # Signing the transaction with KMS key
    tx_singed = sign_transaction(tx_params, params.get_kms_key_id())

    # send transaction
    tx_hash = w3.eth.sendRawTransaction(tx_singed.rawTransaction)
    tx_encoded_hex = w3.toHex(tx_encoded)
    tx_hash = w3.keccak(hexstr=tx_encoded_hex).hex()
    print('translate tx information!!!!!')
    return tx_hash, tx_hash

def assemble_contract(tx_params: dict, 
                      params: EthKmsParams, 
                      eth_checksum_addr: str, 
                      chainid: int, 
                      contract_json: dict, 
                      contract_addr: str, 
                      contract_func: str,
                      contract_params: dict) -> (str):
    abi = contract_json['abi']
    #byte = contract_json['byte']
    contract_attr_checked = Web3.toChecksumAddress(contract_addr)
    contract_instance = w3.eth.contract(abi=abi, address=contract_attr_checked)

    # assemble function in constract
    print(contract_params)
    constract_func_checked = contract_instance.functions[contract_func](
        contract_params["recipient"],
        contract_params["tokenURI"],
        contract_params["id"])
    tx_unsigned = constract_func_checked.buildTransaction(tx_params)
    
    '''
    tx_hash = tx_unsigned.hash()
    # KMSに格納された秘密鍵を使用してデジタル署名
    tx_sig = find_eth_signature(params=params,plaintext=tx_hash)
    tx_eth_recovered_pub_addr = get_recovery_id(msg_hash=tx_hash,
                                                r=tx_sig['r'],
                                                s=tx_sig['s'],
                                                eth_checksum_addr=eth_checksum_addr,
                                                chainid=chainid)
    tx_encoded = encode_transaction(unsigned_transaction=tx_unsigned,
                                    vrs=(
                                        tx_eth_recovered_pub_addr['y_parity'], 
                                        tx_sig['r'], 
                                        tx_sig['s']
                                    ))
    tx_params['data'] = tx_encoded

    # Signing the transaction with KMS key
    tx_singed = sign_transaction(tx_params, params.get_kms_key_id())
    '''

    tx_singed = sign_transaction(tx_unsigned, params.get_kms_key_id())
    tx_hash = w3.eth.sendRawTransaction(tx_singed.rawTransaction)
    #tx_encoded_hex = w3.toHex(tx_encoded)
    #tx_hash = w3.keccak(hexstr=tx_encoded_hex).hex()

    return tx_hash
