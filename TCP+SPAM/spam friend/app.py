from flask import Flask, request, jsonify
import requests
import json
import threading
from byte import Encrypt_ID, encrypt_api
import asyncio
import aiohttp
from google.protobuf.json_format import MessageToJson
import uid_generator_pb2
import like_count_pb2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii

app = Flask(__name__)

# Function to load tokens from token_bd.json
def load_tokens():
    try:
        with open("token_bd.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            tokens = [item["token"] for item in data]
            return tokens
    except Exception as e:
        print(f"Error loading tokens from token_bd.json: {e}")
        return []

# Encryption functions for player info
def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except:
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except:
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

async def get_player_info(uid, token):
    try:
        encrypted_uid = enc(uid)
        if not encrypted_uid:
            return None
            
        url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        edata = bytes.fromhex(encrypted_uid)
        
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers, ssl=False) as response:
                if response.status != 200:
                    return None
                hex_data = await response.read()
                binary = bytes.fromhex(hex_data.hex())
                items = like_count_pb2.Info()
                items.ParseFromString(binary)
                jsone = MessageToJson(items)
                data_info = json.loads(jsone)
                return str(data_info.get('AccountInfo', {}).get('PlayerNickname', ''))
    except:
        return None

def send_friend_request(uid, token, results):
    try:
        encrypted_id = Encrypt_ID(uid)
        if not encrypted_id:
            print(f"❌ Failed to encrypt UID {uid}")
            results["failed"] += 1
            return
            
        payload = f"08a7c4839f1e10{encrypted_id}1801"
        encrypted_payload = encrypt_api(payload)
        
        if not encrypted_payload:
            print(f"❌ Failed to encrypt payload for UID {uid}")
            results["failed"] += 1
            return

        url = "https://clientbp.ggblueshark.com/RequestAddingFriend"
        headers = {
            "Expect": "100-continue",
            "Authorization": f"Bearer {token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB50",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "16",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-N975F Build/PI)",
            "Host": "clientbp.ggblueshark.com",
            "Connection": "close",
            "Accept-Encoding": "gzip, deflate, br"
        }

        response = requests.post(url, headers=headers, data=bytes.fromhex(encrypted_payload), timeout=30)

        if response.status_code == 200:
            print(f"✅ Friend request sent successfully for UID {uid}")
            results["success"] += 1
        else:
            print(f"❌ Friend request failed for UID {uid}, status: {response.status_code}, response: {response.text[:100]}")
            results["failed"] += 1
            
    except requests.exceptions.Timeout:
        print(f"⏰ Timeout for UID {uid}")
        results["failed"] += 1
    except requests.exceptions.RequestException as e:
        print(f"🌐 Request error for UID {uid}: {e}")
        results["failed"] += 1
    except Exception as e:
        print(f"💥 Unexpected error for UID {uid}: {e}")
        results["failed"] += 1

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint to verify the service is running"""
    try:
        tokens = load_tokens()
        return jsonify({
            "status": "healthy",
            "tokens_loaded": len(tokens),
            "service": "spam-friend-api"
        })
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "service": "spam-friend-api"
        }), 500

@app.route("/debug_tokens", methods=["GET"])
def debug_tokens():
    """Debug endpoint to check token status"""
    try:
        tokens = load_tokens()
        token_info = []
        
        for i, token_data in enumerate(tokens[:5]):  # Only check first 5 tokens
            try:
                # Basic token validation - token_data is already the token string
                token = token_data
                if len(token) > 100:  # Basic length check
                    token_info.append({
                        "index": i,
                        "valid": True,
                        "length": len(token)
                    })
                else:
                    token_info.append({
                        "index": i,
                        "valid": False,
                        "error": "Token too short"
                    })
            except Exception as e:
                token_info.append({
                    "index": i,
                    "valid": False,
                    "error": str(e)
                })
        
        return jsonify({
            "total_tokens": len(tokens),
            "tokens": token_info
        })
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500

@app.route("/send_requests", methods=["GET"])
def send_requests():
    uid = request.args.get("uid")
    
    if not uid:
        return jsonify({"error": "uid parameter is required"}), 400

    print(f"🚀 Starting spam friend requests for UID: {uid}")
    
    tokens = load_tokens()
    if not tokens:
        print("❌ No tokens found in token_bd.json")
        return jsonify({"error": "No tokens found from token_bd.json"}), 500

    print(f"📱 Loaded {len(tokens)} tokens from token_bd.json")

    # Get player name (using first token)
    try:
        player_name = asyncio.run(get_player_info(uid, tokens[0]))
        if player_name:
            print(f"👤 Player name: {player_name}")
        else:
            print(f"❓ Could not retrieve player name for UID {uid}")
    except Exception as e:
        print(f"⚠️ Error getting player name: {e}")
        player_name = None

    results = {"success": 0, "failed": 0}
    threads = []

    # Use all available tokens for maximum friend requests
    max_concurrent = len(tokens)
    print(f"🔄 Starting {max_concurrent} concurrent friend requests...")

    for token in tokens:
        thread = threading.Thread(target=send_friend_request, args=(uid, token, results))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    total_requests = results["success"] + results["failed"]
    status = 1 if results["success"] != 0 else 2  # 1 if success, 2 if all failed

    print(f"📊 Results: {results['success']} success, {results['failed']} failed")

    response_data = {
        "success_count": results["success"],
        "failed_count": results["failed"],
        "status": status,
        "total_requests": total_requests
    }
    
    if player_name:
        response_data["player_name"] = player_name

    return jsonify(response_data)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
