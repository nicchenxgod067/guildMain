#!/usr/bin/env python3
"""
Connection Fix Script for TCP Bot
This script helps resolve network connection issues
"""

import socket
import ssl
import time
import requests
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

def test_connection(host, port, use_ssl=True):
    """Test connection to a specific host and port"""
    try:
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    print(f"✅ SSL connection to {host}:{port} successful")
                    return True
        else:
            with socket.create_connection((host, port), timeout=10) as sock:
                print(f"✅ Connection to {host}:{port} successful")
                return True
    except Exception as e:
        print(f"❌ Connection to {host}:{port} failed: {str(e)}")
        return False

def create_robust_session():
    """Create a requests session with retry logic and better error handling"""
    session = requests.Session()
    
    # Configure retry strategy
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # Set longer timeouts
    session.timeout = (30, 60)  # (connect_timeout, read_timeout)
    
    return session

def test_api_endpoints():
    """Test API endpoints to ensure they're accessible"""
    session = create_robust_session()
    
    # Test endpoints
    test_urls = [
        "https://api.brawlstars.com/v1/status",
        "https://httpbin.org/get",
        "https://jsonplaceholder.typicode.com/posts/1"
    ]
    
    for url in test_urls:
        try:
            response = session.get(url, timeout=30)
            print(f"✅ {url}: Status {response.status_code}")
        except Exception as e:
            print(f"❌ {url}: {str(e)}")

def diagnose_network():
    """Diagnose network connectivity issues"""
    print("🔍 Network Diagnostics Starting...")
    print("=" * 50)
    
    # Test basic internet connectivity
    print("\n1. Testing Basic Internet Connectivity:")
    test_connection("8.8.8.8", 53, use_ssl=False)  # Google DNS
    test_connection("1.1.1.1", 53, use_ssl=False)  # Cloudflare DNS
    
    # Test HTTPS connectivity
    print("\n2. Testing HTTPS Connectivity:")
    test_connection("www.google.com", 443, use_ssl=True)
    test_connection("www.github.com", 443, use_ssl=True)
    
    # Test your specific game server
    print("\n3. Testing Game Server Connectivity:")
    test_connection("103.149.162.195", 443, use_ssl=True)
    
    # Test API endpoints
    print("\n4. Testing API Endpoints:")
    test_api_endpoints()
    
    print("\n" + "=" * 50)
    print("🔍 Network Diagnostics Complete!")

def fix_common_issues():
    """Provide solutions for common network issues"""
    print("\n🔧 Common Network Issues & Solutions:")
    print("=" * 50)
    
    print("\n1. Firewall Issues:")
    print("   - Check Windows Firewall settings")
    print("   - Allow Python/your app through firewall")
    print("   - Temporarily disable antivirus to test")
    
    print("\n2. Network Timeout Issues:")
    print("   - Increase connection timeout values")
    print("   - Use connection pooling")
    print("   - Implement retry logic")
    
    print("\n3. Rate Limiting:")
    print("   - Add delays between requests")
    print("   - Use exponential backoff")
    print("   - Implement request queuing")
    
    print("\n4. SSL/TLS Issues:")
    print("   - Update SSL certificates")
    print("   - Check TLS version compatibility")
    print("   - Verify certificate chain")

if __name__ == "__main__":
    print("🚀 TCP Bot Connection Fix Tool")
    print("=" * 50)
    
    # Run diagnostics
    diagnose_network()
    
    # Show solutions
    fix_common_issues()
    
    print("\n💡 Recommendations:")
    print("1. Run this script to identify connection issues")
    print("2. Check firewall and antivirus settings")
    print("3. Test with different network configurations")
    print("4. Consider using a VPN if region-blocked")
    print("5. Implement connection retry logic in your bot")
