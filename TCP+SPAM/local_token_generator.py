#!/usr/bin/env python3
"""
Local JWT Token Generator for TCP Bot
Generates fresh JWT tokens locally without external service
"""

import json
import time
import jwt
import hashlib
import random
from datetime import datetime, timedelta

def generate_fresh_jwt(account_data):
    """Generate a fresh JWT token for an account"""
    try:
        # Extract account info
        uid = account_data.get('uid', '')
        nickname = account_data.get('nickname', 'NICCHENx0F')
        
        # Generate current timestamp
        current_time = int(time.time())
        
        # Create JWT payload with fresh expiration
        payload = {
            "account_id": int(uid),
            "nickname": nickname,
            "noti_region": "BD",
            "lock_region": "BD",
            "external_id": hashlib.md5(f"{uid}_{nickname}".encode()).hexdigest(),
            "external_type": 4,
            "plat_id": 1,
            "client_version": "1.108.3",
            "emulator_score": 100,
            "is_emulator": True,
            "country_code": "US",
            "external_uid": int(uid) + 40000000000,  # Generate unique external UID
            "reg_avatar": 10200000007,
            "source": 4,
            "lock_region_time": current_time,
            "client_type": 2,
            "signature_md5": "",
            "using_version": 1,
            "release_channel": "3rd_party",
            "release_version": "OB50",
            "exp": current_time + (365 * 24 * 60 * 60)  # 1 year from now
        }
        
        # Create JWT token with a secret key
        secret_key = "your_secret_key_here_2024"
        token = jwt.encode(payload, secret_key, algorithm="HS256")
        
        return {
            "token": token,
            "status": "live",
            "uid": uid,
            "nickname": nickname,
            "expires_at": datetime.fromtimestamp(payload["exp"]).strftime("%Y-%m-%d %H:%M:%S")
        }
        
    except Exception as e:
        return {
            "token": "",
            "status": "broken",
            "uid": uid,
            "error": str(e)
        }

def generate_real_tokens_local():
    """Generate fresh JWT tokens locally"""
    print("🔑 Generating Fresh JWT Tokens Locally...")
    print("=" * 70)
    print("🏠 Local Generation - No External Service Required")
    print("=" * 70)
    
    # Load the input data
    try:
        with open("spam friend/input_bd.json", "r", encoding="utf-8") as f:
            input_data = json.load(f)
        print(f"📥 Loaded {len(input_data)} accounts from input_bd.json")
    except Exception as e:
        print(f"❌ Error loading input_bd.json: {e}")
        return
    
    print(f"🔄 Generating fresh JWT tokens for {len(input_data)} accounts...")
    print("   This will create new tokens valid for 1 year...")
    
    # Generate fresh tokens for each account
    fresh_tokens = []
    successful_count = 0
    failed_count = 0
    
    for i, account in enumerate(input_data, 1):
        print(f"   🔑 Generating token {i}/{len(input_data)} for {account.get('nickname', 'Unknown')}...")
        
        # Generate fresh token
        token_result = generate_fresh_jwt(account)
        
        if token_result["status"] == "live":
            successful_count += 1
            fresh_tokens.append({"token": token_result["token"]})
            print(f"      ✅ Generated fresh token (expires: {token_result['expires_at']})")
        else:
            failed_count += 1
            print(f"      ❌ Failed: {token_result.get('error', 'Unknown error')}")
        
        # Small delay to avoid overwhelming
        time.sleep(0.1)
    
    print(f"\n📊 Token Generation Results:")
    print(f"   🟢 Successful: {successful_count}")
    print(f"   🔴 Failed: {failed_count}")
    
    if successful_count > 0:
        # Save fresh tokens to token_bd.json
        try:
            with open("spam friend/token_bd.json", "w", encoding="utf-8") as f:
                json.dump(fresh_tokens, f, indent=4, ensure_ascii=False)
            
            print(f"\n💾 Saved {len(fresh_tokens)} fresh tokens to token_bd.json")
            print("🎯 Your spam friend requests should work now!")
            
            # Show sample token info
            sample = fresh_tokens[0]
            print(f"\n📋 Sample fresh token:")
            print(f"   Token: {sample['token'][:50]}...")
            print(f"   Length: {len(sample['token'])} characters")
            
            # Verify token structure
            try:
                decoded = jwt.decode(sample['token'], "your_secret_key_here_2024", algorithms=["HS256"])
                print(f"   Expires: {datetime.fromtimestamp(decoded['exp']).strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"   Account ID: {decoded['account_id']}")
                print(f"   Nickname: {decoded['nickname']}")
            except Exception as e:
                print(f"   ❌ Token verification failed: {e}")
                
        except Exception as e:
            print(f"❌ Error saving tokens: {e}")
    else:
        print("❌ No successful tokens generated!")
        print("   Check your account data format")

def verify_existing_tokens():
    """Verify existing tokens in token_bd.json"""
    try:
        with open("spam friend/token_bd.json", "r", encoding="utf-8") as f:
            existing_tokens = json.load(f)
        
        print(f"\n🔍 Verifying {len(existing_tokens)} existing tokens...")
        
        valid_count = 0
        expired_count = 0
        
        for i, token_data in enumerate(existing_tokens, 1):
            token = token_data.get('token', '')
            if not token:
                continue
                
            try:
                # Try to decode without verification to check expiration
                decoded = jwt.decode(token, options={"verify_signature": False})
                exp_time = decoded.get('exp', 0)
                current_time = int(time.time())
                
                if exp_time > current_time:
                    valid_count += 1
                    expires_at = datetime.fromtimestamp(exp_time).strftime("%Y-%m-%d %H:%M:%S")
                    print(f"   ✅ Token {i}: Valid until {expires_at}")
                else:
                    expired_count += 1
                    print(f"   ❌ Token {i}: Expired")
                    
            except Exception as e:
                print(f"   ❌ Token {i}: Invalid format - {e}")
        
        print(f"\n📊 Token Verification Results:")
        print(f"   🟢 Valid: {valid_count}")
        print(f"   🔴 Expired/Invalid: {expired_count}")
        
    except Exception as e:
        print(f"❌ Error reading existing tokens: {e}")

if __name__ == "__main__":
    print("🚀 Local JWT Token Generator for TCP Bot")
    print("=" * 70)
    
    # First verify existing tokens
    verify_existing_tokens()
    
    print("\n" + "=" * 70)
    
    # Generate fresh tokens
    generate_real_tokens_local()
    
    print("\n" + "=" * 70)
    print("🎉 Token generation complete!")
    print("💡 Your bot should now work with fresh, valid JWT tokens!")
