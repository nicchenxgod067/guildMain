# -*- coding: utf-8 -*-
# Combined Protocol Buffer and Encryption Utilities
# This file combines functionality from like_pb2.py, like_count_pb2.py, uid_generator_pb2.py, and byte.py

import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from google.protobuf import descriptor_pb2
from google.protobuf import message
from google.protobuf import reflection
from google.protobuf import descriptor_pool
from google.protobuf import json_format
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import json
import os
import binascii
import requests
import asyncio
import aiohttp

# Create a descriptor pool
_pool = descriptor_pool.Default()

# ===========================================
# Protocol Buffer Message Definitions
# ===========================================

def create_message_class(message_name, fields):
    """Dynamically create a message class with the given fields."""
    # Create property getter and setter for a field
    def create_property(field_name):
        def getter(self):
            return getattr(self, f'_{field_name}')
        def setter(self, value):
            setattr(self, f'_{field_name}', value)
        return property(getter, setter)
    
    class DynamicMessage:
        def __init__(self, **kwargs):
            # Initialize all fields with default values
            for field, default in fields.items():
                setattr(self, f'_{field}', default)
            # Set provided values
            for field, value in kwargs.items():
                if field in fields:  # Only set fields that were defined
                    setattr(self, f'_{field}', value)
    
    # Add properties for each field
    for field_name in fields.keys():
        setattr(DynamicMessage, field_name, create_property(field_name))
    
    # Set the message name for better debugging
    DynamicMessage.__name__ = message_name
    
    return DynamicMessage

# Define message classes
Like = create_message_class('Like', {
    'uid': 0,  # int64
    'region': ''  # string
})

Generator = create_message_class('Generator', {
    'saturn_': 0,  # int64
    'garena': 0    # int64
})

BasicInfo = create_message_class('BasicInfo', {
    'UID': 0,              # int64
    'PlayerNickname': '',   # string
    'Likes': 0             # int64
})

Info = create_message_class('Info', {
    'AccountInfo': None  # BasicInfo
})

# Add message classes to globals for easier access
_globals = globals()
_globals['like'] = Like
_globals['generator'] = Generator
_globals['BasicInfo'] = BasicInfo
_globals['Info'] = Info

# ===========================================
# Encryption/Decryption Utilities (from byte.py)
# ===========================================

# Character sets for encoding/decoding
DECODING_CHARS = [
    '80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f',
    '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f',
    'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af',
    'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf',
    'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf',
    'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df',
    'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef',
    'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff'
]

ENCODING_CHARS = [
    '1', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f',
    '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f',
    '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f',
    '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f',
    '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f',
    '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f',
    '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f',
    '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f'
]

# AES Encryption/Decryption
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

def encrypt_message(plaintext):
    """Encrypt plaintext using AES-CBC with PKCS7 padding."""
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decrypt_message(cipher_text):
    """Decrypt ciphertext using AES-CBC with PKCS7 padding."""
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        plain_text = unpad(cipher.decrypt(bytes.fromhex(cipher_text)), AES.block_size)
        return plain_text
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

# ID Encoding/Decoding
def encode_uid(uid):
    """Encode a UID to a hexadecimal string."""
    try:
        uid = int(uid)
        x = uid / 128
        
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                if x > 128:
                    x = x / 128
                    strx = int(x)
                    y = (x - int(strx)) * 128
                    stry = str(int(y))
                    z = (y - int(stry)) * 128
                    strz = str(int(z))
                    n = (z - int(strz)) * 128
                    strn = str(int(n))
                    m = (n - int(strn)) * 128
                    return DECODING_CHARS[int(m)] + DECODING_CHARS[int(n)] + \
                           DECODING_CHARS[int(z)] + DECODING_CHARS[int(y)] + \
                           ENCODING_CHARS[int(x)]
                else:
                    strx = int(x)
                    y = (x - int(strx)) * 128
                    stry = str(int(y))
                    z = (y - int(stry)) * 128
                    strz = str(int(z))
                    n = (z - int(strz)) * 128
                    strn = str(int(n))
                    return DECODING_CHARS[int(n)] + DECODING_CHARS[int(z)] + \
                           DECODING_CHARS[int(y)] + ENCODING_CHARS[int(x)]
    except Exception as e:
        print(f"UID encoding error: {e}")
    return None

def decode_uid(encoded_uid):
    """Decode a hexadecimal string to a UID."""
    try:
        if not encoded_uid or len(encoded_uid) not in [8, 10]:
            return None
            
        w = 128
        if len(encoded_uid) == 10:
            x5 = encoded_uid[8:10]
            x4 = encoded_uid[6:8]
            x3 = encoded_uid[4:6]
            x2 = encoded_uid[2:4]
            x1 = encoded_uid[0:2]
            
            w = w * 128 * 128 * 128  # 128^3 for 5-byte encoding
            return str(w * ENCODING_CHARS.index(x5) + 
                     (DECODING_CHARS.index(x2) * 128) + 
                     DECODING_CHARS.index(x1) + 
                     (DECODING_CHARS.index(x3) * 128 * 128) + 
                     (DECODING_CHARS.index(x4) * 128 * 128 * 128))
        else:  # 8-byte encoding
            x4 = encoded_uid[6:8]
            x3 = encoded_uid[4:6]
            x2 = encoded_uid[2:4]
            x1 = encoded_uid[0:2]
            
            w = w * 128 * 128  # 128^2 for 4-byte encoding
            return str(w * ENCODING_CHARS.index(x4) + 
                     (DECODING_CHARS.index(x2) * 128) + 
                     DECODING_CHARS.index(x1) + 
                     (DECODING_CHARS.index(x3) * 128 * 128))
    except Exception as e:
        print(f"UID decoding error: {e}")
    return None

# Protocol Buffer Helper Functions
def create_uid_generator(uid):
    """Create a UID generator protobuf message."""
    try:
        # Create a new generator message with initial values
        generator = Generator(saturn_=int(uid), garena=1)
        
        # Manually serialize the message
        # Format: field_number << 3 | wire_type
        # For int64 (wire_type=0), the format is: (field_number << 3) | 0, followed by the varint value
        
        # Serialize saturn_ (field 1, int64)
        saturn_bytes = []
        val = generator.saturn_
        if val < 0:
            val += (1 << 64)  # Convert to unsigned 64-bit
        while val > 0x7f:
            saturn_bytes.append((val & 0x7f) | 0x80)
            val >>= 7
        saturn_bytes.append(val)
        
        # Serialize garena (field 2, int64)
        garena_bytes = []
        val = generator.garena
        if val < 0:
            val += (1 << 64)  # Convert to unsigned 64-bit
        while val > 0x7f:
            garena_bytes.append((val & 0x7f) | 0x80)
            val >>= 7
        garena_bytes.append(val)
        
        # Combine the serialized fields
        result = bytearray()
        # Field 1 (saturn_)
        result.extend([(1 << 3) | 0])
        result.extend(saturn_bytes)
        # Field 2 (garena)
        result.extend([(2 << 3) | 0])
        result.extend(garena_bytes)
        
        return bytes(result)
    except Exception as e:
        print(f"Error creating UID generator: {e}")
        import traceback
        traceback.print_exc()
        return None

def parse_like_info(binary_data):
    """Parse like info from binary protobuf data."""
    try:
        result = {
            'AccountInfo': {
                'UID': 0,
                'PlayerNickname': '',
                'Likes': 0
            }
        }
        
        # Manually parse the binary data
        ptr = 0
        while ptr < len(binary_data):
            # Read field number and wire type
            if ptr >= len(binary_data):
                break
                
            b = binary_data[ptr]
            field_num = b >> 3
            wire_type = b & 0x7
            ptr += 1
            
            if field_num == 1 and wire_type == 2:  # Field 1, length-delimited (nested message)
                # Read the length of the nested message
                length = 0
                shift = 0
                while True:
                    if ptr >= len(binary_data):
                        break
                    b = binary_data[ptr]
                    ptr += 1
                    length |= (b & 0x7f) << shift
                    if not (b & 0x80):
                        break
                    shift += 7
                
                # Parse the nested BasicInfo message
                basic_info = {'UID': 0, 'PlayerNickname': '', 'Likes': 0}
                nested_ptr = 0
                while nested_ptr < length and ptr + nested_ptr < len(binary_data):
                    b = binary_data[ptr + nested_ptr]
                    nested_field_num = b >> 3
                    nested_wire_type = b & 0x7
                    nested_ptr += 1
                    
                    if nested_field_num == 1 and nested_wire_type == 0:  # Field 1: UID (int64)
                        # Read varint
                        val = 0
                        shift = 0
                        while ptr + nested_ptr < len(binary_data):
                            b = binary_data[ptr + nested_ptr]
                            nested_ptr += 1
                            val |= (b & 0x7f) << shift
                            if not (b & 0x80):
                                break
                            shift += 7
                        basic_info['UID'] = val
                    
                    # Add more field parsing as needed
                    # For example, for PlayerNickname (field 3, string)
                    elif nested_field_num == 3 and nested_wire_type == 2:  # Field 3: PlayerNickname (string)
                        str_length = 0
                        shift = 0
                        while ptr + nested_ptr < len(binary_data):
                            b = binary_data[ptr + nested_ptr]
                            nested_ptr += 1
                            str_length |= (b & 0x7f) << shift
                            if not (b & 0x80):
                                break
                            shift += 7
                        
                        # Read the string
                        if ptr + nested_ptr + str_length <= len(binary_data):
                            basic_info['PlayerNickname'] = binary_data[ptr + nested_ptr:ptr + nested_ptr + str_length].decode('utf-8')
                            nested_ptr += str_length
                
                result['AccountInfo'] = basic_info
                ptr += length
        
        return result
    except Exception as e:
        print(f"Error parsing like info: {e}")
        import traceback
        traceback.print_exc()
        return None

# API Encryption/Decryption
def encrypt_api(plain_text):
    """Encrypt data for API requests."""
    try:
        plain_text = bytes.fromhex(plain_text)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
        return cipher_text.hex()
    except Exception as e:
        print(f"API encryption error: {e}")
        return None

def decrypt_api(cipher_text):
    """Decrypt data from API responses."""
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        plain_text = unpad(cipher.decrypt(bytes.fromhex(cipher_text)), AES.block_size)
        return plain_text.hex()
    except Exception as e:
        print(f"API decryption error: {e}")
        return None# -*- coding: utf-8 -*-
# Combined Protocol Buffer and Encryption Utilities
# This file combines functionality from like_pb2.py, like_count_pb2.py, uid_generator_pb2.py, and byte.py

import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from google.protobuf import descriptor_pb2
from google.protobuf import message
from google.protobuf import reflection
from google.protobuf import descriptor_pool
from google.protobuf import json_format
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import json
import os
import binascii
import requests
import asyncio
import aiohttp

# Create a descriptor pool
_pool = descriptor_pool.Default()

# ===========================================
# Protocol Buffer Message Definitions
# ===========================================

def create_message_class(message_name, fields):
    """Dynamically create a message class with the given fields."""
    # Create property getter and setter for a field
    def create_property(field_name):
        def getter(self):
            return getattr(self, f'_{field_name}')
        def setter(self, value):
            setattr(self, f'_{field_name}', value)
        return property(getter, setter)
    
    class DynamicMessage:
        def __init__(self, **kwargs):
            # Initialize all fields with default values
            for field, default in fields.items():
                setattr(self, f'_{field}', default)
            # Set provided values
            for field, value in kwargs.items():
                if field in fields:  # Only set fields that were defined
                    setattr(self, f'_{field}', value)
    
    # Add properties for each field
    for field_name in fields.keys():
        setattr(DynamicMessage, field_name, create_property(field_name))
    
    # Set the message name for better debugging
    DynamicMessage.__name__ = message_name
    
    return DynamicMessage

# Define message classes
Like = create_message_class('Like', {
    'uid': 0,  # int64
    'region': ''  # string
})

Generator = create_message_class('Generator', {
    'saturn_': 0,  # int64
    'garena': 0    # int64
})

BasicInfo = create_message_class('BasicInfo', {
    'UID': 0,              # int64
    'PlayerNickname': '',   # string
    'Likes': 0             # int64
})

Info = create_message_class('Info', {
    'AccountInfo': None  # BasicInfo
})

# Add message classes to globals for easier access
_globals = globals()
_globals['like'] = Like
_globals['generator'] = Generator
_globals['BasicInfo'] = BasicInfo
_globals['Info'] = Info

# ===========================================
# Encryption/Decryption Utilities (from byte.py)
# ===========================================

# Character sets for encoding/decoding
DECODING_CHARS = [
    '80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f',
    '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f',
    'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af',
    'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf',
    'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf',
    'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df',
    'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef',
    'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff'
]

ENCODING_CHARS = [
    '1', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f',
    '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f',
    '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f',
    '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f',
    '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f',
    '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f',
    '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f',
    '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f'
]

# AES Encryption/Decryption
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

def encrypt_message(plaintext):
    """Encrypt plaintext using AES-CBC with PKCS7 padding."""
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decrypt_message(cipher_text):
    """Decrypt ciphertext using AES-CBC with PKCS7 padding."""
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        plain_text = unpad(cipher.decrypt(bytes.fromhex(cipher_text)), AES.block_size)
        return plain_text
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

# ID Encoding/Decoding
def encode_uid(uid):
    """Encode a UID to a hexadecimal string."""
    try:
        uid = int(uid)
        x = uid / 128
        
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                if x > 128:
                    x = x / 128
                    strx = int(x)
                    y = (x - int(strx)) * 128
                    stry = str(int(y))
                    z = (y - int(stry)) * 128
                    strz = str(int(z))
                    n = (z - int(strz)) * 128
                    strn = str(int(n))
                    m = (n - int(strn)) * 128
                    return DECODING_CHARS[int(m)] + DECODING_CHARS[int(n)] + \
                           DECODING_CHARS[int(z)] + DECODING_CHARS[int(y)] + \
                           ENCODING_CHARS[int(x)]
                else:
                    strx = int(x)
                    y = (x - int(strx)) * 128
                    stry = str(int(y))
                    z = (y - int(stry)) * 128
                    strz = str(int(z))
                    n = (z - int(strz)) * 128
                    strn = str(int(n))
                    return DECODING_CHARS[int(n)] + DECODING_CHARS[int(z)] + \
                           DECODING_CHARS[int(y)] + ENCODING_CHARS[int(x)]
    except Exception as e:
        print(f"UID encoding error: {e}")
    return None

def decode_uid(encoded_uid):
    """Decode a hexadecimal string to a UID."""
    try:
        if not encoded_uid or len(encoded_uid) not in [8, 10]:
            return None
            
        w = 128
        if len(encoded_uid) == 10:
            x5 = encoded_uid[8:10]
            x4 = encoded_uid[6:8]
            x3 = encoded_uid[4:6]
            x2 = encoded_uid[2:4]
            x1 = encoded_uid[0:2]
            
            w = w * 128 * 128 * 128  # 128^3 for 5-byte encoding
            return str(w * ENCODING_CHARS.index(x5) + 
                     (DECODING_CHARS.index(x2) * 128) + 
                     DECODING_CHARS.index(x1) + 
                     (DECODING_CHARS.index(x3) * 128 * 128) + 
                     (DECODING_CHARS.index(x4) * 128 * 128 * 128))
        else:  # 8-byte encoding
            x4 = encoded_uid[6:8]
            x3 = encoded_uid[4:6]
            x2 = encoded_uid[2:4]
            x1 = encoded_uid[0:2]
            
            w = w * 128 * 128  # 128^2 for 4-byte encoding
            return str(w * ENCODING_CHARS.index(x4) + 
                     (DECODING_CHARS.index(x2) * 128) + 
                     DECODING_CHARS.index(x1) + 
                     (DECODING_CHARS.index(x3) * 128 * 128))
    except Exception as e:
        print(f"UID decoding error: {e}")
    return None

# Protocol Buffer Helper Functions
def create_uid_generator(uid):
    """Create a UID generator protobuf message."""
    try:
        # Create a new generator message with initial values
        generator = Generator(saturn_=int(uid), garena=1)
        
        # Manually serialize the message
        # Format: field_number << 3 | wire_type
        # For int64 (wire_type=0), the format is: (field_number << 3) | 0, followed by the varint value
        
        # Serialize saturn_ (field 1, int64)
        saturn_bytes = []
        val = generator.saturn_
        if val < 0:
            val += (1 << 64)  # Convert to unsigned 64-bit
        while val > 0x7f:
            saturn_bytes.append((val & 0x7f) | 0x80)
            val >>= 7
        saturn_bytes.append(val)
        
        # Serialize garena (field 2, int64)
        garena_bytes = []
        val = generator.garena
        if val < 0:
            val += (1 << 64)  # Convert to unsigned 64-bit
        while val > 0x7f:
            garena_bytes.append((val & 0x7f) | 0x80)
            val >>= 7
        garena_bytes.append(val)
        
        # Combine the serialized fields
        result = bytearray()
        # Field 1 (saturn_)
        result.extend([(1 << 3) | 0])
        result.extend(saturn_bytes)
        # Field 2 (garena)
        result.extend([(2 << 3) | 0])
        result.extend(garena_bytes)
        
        return bytes(result)
    except Exception as e:
        print(f"Error creating UID generator: {e}")
        import traceback
        traceback.print_exc()
        return None

def parse_like_info(binary_data):
    """Parse like info from binary protobuf data."""
    try:
        result = {
            'AccountInfo': {
                'UID': 0,
                'PlayerNickname': '',
                'Likes': 0
            }
        }
        
        # Manually parse the binary data
        ptr = 0
        while ptr < len(binary_data):
            # Read field number and wire type
            if ptr >= len(binary_data):
                break
                
            b = binary_data[ptr]
            field_num = b >> 3
            wire_type = b & 0x7
            ptr += 1
            
            if field_num == 1 and wire_type == 2:  # Field 1, length-delimited (nested message)
                # Read the length of the nested message
                length = 0
                shift = 0
                while True:
                    if ptr >= len(binary_data):
                        break
                    b = binary_data[ptr]
                    ptr += 1
                    length |= (b & 0x7f) << shift
                    if not (b & 0x80):
                        break
                    shift += 7
                
                # Parse the nested BasicInfo message
                basic_info = {'UID': 0, 'PlayerNickname': '', 'Likes': 0}
                nested_ptr = 0
                while nested_ptr < length and ptr + nested_ptr < len(binary_data):
                    b = binary_data[ptr + nested_ptr]
                    nested_field_num = b >> 3
                    nested_wire_type = b & 0x7
                    nested_ptr += 1
                    
                    if nested_field_num == 1 and nested_wire_type == 0:  # Field 1: UID (int64)
                        # Read varint
                        val = 0
                        shift = 0
                        while ptr + nested_ptr < len(binary_data):
                            b = binary_data[ptr + nested_ptr]
                            nested_ptr += 1
                            val |= (b & 0x7f) << shift
                            if not (b & 0x80):
                                break
                            shift += 7
                        basic_info['UID'] = val
                    
                    # Add more field parsing as needed
                    # For example, for PlayerNickname (field 3, string)
                    elif nested_field_num == 3 and nested_wire_type == 2:  # Field 3: PlayerNickname (string)
                        str_length = 0
                        shift = 0
                        while ptr + nested_ptr < len(binary_data):
                            b = binary_data[ptr + nested_ptr]
                            nested_ptr += 1
                            str_length |= (b & 0x7f) << shift
                            if not (b & 0x80):
                                break
                            shift += 7
                        
                        # Read the string
                        if ptr + nested_ptr + str_length <= len(binary_data):
                            basic_info['PlayerNickname'] = binary_data[ptr + nested_ptr:ptr + nested_ptr + str_length].decode('utf-8')
                            nested_ptr += str_length
                
                result['AccountInfo'] = basic_info
                ptr += length
        
        return result
    except Exception as e:
        print(f"Error parsing like info: {e}")
        import traceback
        traceback.print_exc()
        return None

# API Encryption/Decryption
def encrypt_api(plain_text):
    """Encrypt data for API requests."""
    try:
        plain_text = bytes.fromhex(plain_text)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
        return cipher_text.hex()
    except Exception as e:
        print(f"API encryption error: {e}")
        return None

def decrypt_api(cipher_text):
    """Decrypt data from API responses."""
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        plain_text = unpad(cipher.decrypt(bytes.fromhex(cipher_text)), AES.block_size)
        return plain_text.hex()
    except Exception as e:
        print(f"API decryption error: {e}")
        return None