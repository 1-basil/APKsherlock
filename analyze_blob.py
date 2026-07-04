import os
import struct

def analyze_blob(filepath):
    print(f"Analyzing {os.path.basename(filepath)}")
    with open(filepath, 'rb') as f:
        data = f.read()
    
    print(f"Size: {len(data)} bytes")
    print(f"First 32 bytes: {data[:32].hex()}")
    print(f"Last 32 bytes: {data[-32:].hex()}")
    
    # Try simple XOR against DEX magic 'dex\n035\0'
    dex_magic = b'dex\n035\0'
    for i in range(256):
        xored = bytes([b ^ i for b in data[:8]])
        if xored == dex_magic:
            print(f"Found single-byte XOR key: 0x{i:02x}")
            return
            
    # Try finding ZIP magic 'PK\x03\x04'
    zip_magic = b'PK\x03\x04'
    for i in range(256):
        xored = bytes([b ^ i for b in data[:4]])
        if xored == zip_magic:
            print(f"Found single-byte XOR key for ZIP: 0x{i:02x}")
            return
            
    print("No simple single-byte XOR key found for DEX or ZIP magic.")

if __name__ == '__main__':
    target = r"C:\Traceguard_Trial\forensicdroid\analysis_mparivahanv3_1783181191\nested_apks\assets_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_ۦۖ۫_54fb10f4"
    analyze_blob(target)
