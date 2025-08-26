#!/usr/bin/env python3
"""
Real JWT Token Generator - Uses your hosted JWT converter service
Service URL: https://tcp1-two.vercel.app/jwt/
"""

import requests
import json
import time

def generate_real_tokens():
    print("🔑 Generating Real JWT Tokens from Your Hosted JWT Converter...")
    print("=" * 70)
    print("🌐 Service: https://tcp1-two.vercel.app/jwt/")
    print("=" * 70)
    
    # Load the input data
    try:
        with open("spam friend/input_bd.json", "r", encoding="utf-8") as f:
            input_data = json.load(f)
        print(f"📥 Loaded {len(input_data)} accounts from input_bd.json")
    except Exception as e:
        print(f"❌ Error loading input_bd.json: {e}")
        return
    
    # Your hosted JWT converter service URL - Correct endpoint from Vercel dashboard
    jwt_service_url = "https://tcp1-two.vercel.app/jwt/cloudgen_jwt"
    
    print(f"🔄 Sending data to your hosted JWT converter at {jwt_service_url}")
    print("   This will generate real, authentic JWT tokens from the game servers...")
    
    try:
        # Send the data to your hosted JWT converter service
        response = requests.post(
            jwt_service_url,
            json=input_data,
            headers={"Content-Type": "application/json"},
            timeout=300  # 5 minutes timeout
        )
        
        if response.status_code == 200:
            tokens_data = response.json()
            print(f"✅ Successfully generated {len(tokens_data)} tokens!")
            
            # Filter successful tokens
            successful_tokens = [item for item in tokens_data if item.get("status") == "live"]
            failed_tokens = [item for item in tokens_data if item.get("status") == "broken"]
            
            print(f"   🟢 Live tokens: {len(successful_tokens)}")
            print(f"   🔴 Broken tokens: {len(failed_tokens)}")
            
            if failed_tokens:
                print("\n⚠️  Failed tokens:")
                for item in failed_tokens[:5]:  # Show first 5 failures
                    print(f"      UID {item.get('uid')}: {item.get('error', 'Unknown error')}")
            
            # Save successful tokens to token_bd.json
            if successful_tokens:
                output_data = [{"token": item["token"]} for item in successful_tokens]
                
                with open("spam friend/token_bd.json", "w", encoding="utf-8") as f:
                    json.dump(output_data, f, indent=4, ensure_ascii=False)
                
                print(f"\n💾 Saved {len(output_data)} real tokens to token_bd.json")
                print("🎯 Now your spam friend requests should work!")
                
                # Show sample token info
                sample = successful_tokens[0]
                print(f"\n📋 Sample token info:")
                print(f"   UID: {sample.get('uid')}")
                print(f"   Status: {sample.get('status')}")
                print(f"   Token: {sample.get('token', '')[:50]}...")
                
            else:
                print("❌ No successful tokens generated!")
                print("   Check your hosted JWT converter service for errors")
                
        else:
            print(f"❌ JWT converter service error: {response.status_code}")
            print(f"   Response: {response.text[:500]}")
            print(f"   Headers: {dict(response.headers)}")
            print(f"   URL: {jwt_service_url}")
            
            # Try to get more info about the error
            if response.status_code == 500:
                print("   🔍 500 Error suggests server-side issue")
                print("   💡 Check your Vercel deployment logs")
            elif response.status_code == 404:
                print("   🔍 404 Error suggests wrong endpoint")
                print("   💡 Check the correct API endpoint URL")
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to your hosted JWT converter service!")
        print("   Check if https://tcp1-two.vercel.app/jwt/ is accessible")
    except Exception as e:
        print(f"❌ Error generating tokens: {e}")

if __name__ == "__main__":
    generate_real_tokens()
