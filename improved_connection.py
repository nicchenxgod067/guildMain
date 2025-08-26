#!/usr/bin/env python3
"""
Improved Connection Handler for TCP Bot
Includes retry logic, alternative servers, and better error handling
"""

import socket
import ssl
import time
import asyncio
import random
from typing import List, Tuple, Optional

class ImprovedConnectionHandler:
    def __init__(self):
        # Alternative server configurations
        self.server_configs = [
            {"ip": "103.149.162.195", "port": 443, "name": "Primary Server"},
            {"ip": "103.149.162.195", "port": 80, "name": "Primary Server (HTTP)"},
            {"ip": "103.149.162.196", "port": 443, "name": "Alternative Server 1"},
            {"ip": "103.149.162.197", "port": 443, "name": "Alternative Server 2"},
        ]
        
        # Connection settings
        self.connection_timeout = 30
        self.retry_attempts = 3
        self.retry_delay = 5
        
    async def test_server_connectivity(self, ip: str, port: int, use_ssl: bool = True) -> bool:
        """Test if a specific server is reachable"""
        try:
            # Use asyncio for non-blocking connection test
            future = asyncio.get_event_loop().run_in_executor(
                None, self._test_sync_connection, ip, port, use_ssl
            )
            result = await asyncio.wait_for(future, timeout=15)
            return result
        except asyncio.TimeoutError:
            print(f"⏰ Connection test to {ip}:{port} timed out")
            return False
        except Exception as e:
            print(f"❌ Connection test to {ip}:{port} failed: {str(e)}")
            return False
    
    def _test_sync_connection(self, ip: str, port: int, use_ssl: bool) -> bool:
        """Synchronous connection test"""
        try:
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((ip, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=ip) as ssock:
                        print(f"✅ SSL connection to {ip}:{port} successful")
                        return True
            else:
                with socket.create_connection((ip, port), timeout=10) as sock:
                    print(f"✅ Connection to {ip}:{port} successful")
                    return True
        except Exception as e:
            print(f"❌ Connection to {ip}:{port} failed: {str(e)}")
            return False
    
    async def find_working_server(self) -> Optional[Tuple[str, int, bool]]:
        """Find a working server from the list"""
        print("🔍 Searching for working servers...")
        
        for config in self.server_configs:
            ip = config["ip"]
            port = config["port"]
            name = config["name"]
            
            print(f"\n🔍 Testing {name} ({ip}:{port})...")
            
            # Test both SSL and non-SSL
            for use_ssl in [True, False]:
                if await self.test_server_connectivity(ip, port, use_ssl):
                    print(f"🎯 Found working server: {name} ({ip}:{port}) {'SSL' if use_ssl else 'HTTP'}")
                    return ip, port, use_ssl
            
            # Add delay between tests
            await asyncio.sleep(1)
        
        print("❌ No working servers found")
        return None
    
    async def establish_connection(self, ip: str, port: int, use_ssl: bool = True) -> Optional[Tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
        """Establish a connection with retry logic"""
        for attempt in range(self.retry_attempts):
            try:
                print(f"🔄 Connection attempt {attempt + 1}/{self.retry_attempts} to {ip}:{port}")
                
                if use_ssl:
                    # SSL connection
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port, ssl=context),
                        timeout=self.connection_timeout
                    )
                else:
                    # Plain TCP connection
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=self.connection_timeout
                    )
                
                print(f"✅ Connection established to {ip}:{port}")
                return reader, writer
                
            except asyncio.TimeoutError:
                print(f"⏰ Connection attempt {attempt + 1} timed out")
            except Exception as e:
                print(f"❌ Connection attempt {attempt + 1} failed: {str(e)}")
            
            if attempt < self.retry_attempts - 1:
                delay = self.retry_delay * (2 ** attempt)  # Exponential backoff
                print(f"⏳ Waiting {delay} seconds before retry...")
                await asyncio.sleep(delay)
        
        print(f"❌ Failed to establish connection after {self.retry_attempts} attempts")
        return None
    
    async def maintain_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, 
                                ip: str, port: int, bot_name: str):
        """Maintain connection with heartbeat and error handling"""
        try:
            print(f"🔗 Maintaining connection for bot {bot_name} to {ip}:{port}")
            
            while True:
                try:
                    # Send heartbeat every 30 seconds
                    heartbeat_data = b'\x00'  # Simple heartbeat
                    writer.write(heartbeat_data)
                    await writer.drain()
                    
                    # Wait for data with timeout
                    try:
                        data = await asyncio.wait_for(reader.read(1024), timeout=30.0)
                        if not data:
                            print(f"📡 Bot {bot_name} received empty data, connection may be closed")
                            break
                        
                        print(f"📡 Bot {bot_name} received {len(data)} bytes")
                        
                    except asyncio.TimeoutError:
                        # Timeout is normal for heartbeat
                        pass
                    
                except Exception as e:
                    print(f"❌ Error in connection loop for bot {bot_name}: {str(e)}")
                    break
                    
        except Exception as e:
            print(f"❌ Fatal error in connection maintenance for bot {bot_name}: {str(e)}")
        finally:
            print(f"🔌 Closing connection for bot {bot_name}")
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass

async def main():
    """Test the improved connection handler"""
    handler = ImprovedConnectionHandler()
    
    # Find working server
    server_info = await handler.find_working_server()
    
    if server_info:
        ip, port, use_ssl = server_info
        print(f"\n🎯 Attempting to connect to working server: {ip}:{port}")
        
        # Try to establish connection
        connection = await handler.establish_connection(ip, port, use_ssl)
        
        if connection:
            reader, writer = connection
            print("✅ Connection test successful!")
            
            # Close test connection
            writer.close()
            await writer.wait_closed()
        else:
            print("❌ Failed to establish connection")
    else:
        print("\n💡 Recommendations:")
        print("1. Check if the game server is down for maintenance")
        print("2. Try using a VPN to bypass regional restrictions")
        print("3. Contact the game developers for server status")
        print("4. Check if the server IP has changed")
        print("5. Implement fallback to local game mode")

if __name__ == "__main__":
    asyncio.run(main())
