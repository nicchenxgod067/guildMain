#!/usr/bin/env python3
"""
Fix protobuf compatibility issues by removing runtime_version imports
"""

import os
import re

def fix_protobuf_file(filepath):
    """Fix a single protobuf file by removing runtime_version imports"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Remove runtime_version import
        content = re.sub(
            r'from google\.protobuf import runtime_version as _runtime_version\n',
            '',
            content
        )
        
        # Remove runtime_version validation
        content = re.sub(
            r'_runtime_version\.ValidateProtobufRuntimeVersion\(\s*_runtime_version\.Domain\.PUBLIC,\s*\d+,\s*\d+,\s*\d+,\s*[\'"]*[\'"],\s*[\'"].*?[\'"]\s*\)\n',
            '',
            content
        )
        
        # Write back the fixed content
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"✅ Fixed: {filepath}")
        return True
    except Exception as e:
        print(f"❌ Error fixing {filepath}: {e}")
        return False

def main():
    """Fix all protobuf files in the TCP BD BOT directory"""
    print("🔧 Fixing protobuf compatibility issues...")
    
    # Directory containing protobuf files
    bot_dir = "TCP BD BOT"
    
    # Find all protobuf files
    protobuf_files = []
    for file in os.listdir(bot_dir):
        if file.endswith('_pb2.py'):
            protobuf_files.append(os.path.join(bot_dir, file))
    
    print(f"📁 Found {len(protobuf_files)} protobuf files to fix")
    
    # Fix each file
    fixed_count = 0
    for filepath in protobuf_files:
        if fix_protobuf_file(filepath):
            fixed_count += 1
    
    print(f"\n🎉 Fixed {fixed_count}/{len(protobuf_files)} protobuf files")
    print("✅ TCP BD BOT should now work with protobuf 3.20.3")

if __name__ == "__main__":
    main()
