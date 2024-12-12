import os
import sys
import json
import base64

def xor_decrypt(data: str, key: str) -> bytes:
    key_bytes = key.encode('utf-8')
    decrypted = bytearray(len(data))
    for i in range(len(data)):
        decrypted[i] = data[i] ^ key_bytes[i % len(key_bytes)]
    return bytes(decrypted)

encoded_base64_file = sys.argv[1]

with open(encoded_base64_file, "r") as f:
    json_data = json.load(f)

base64_encoded_data, encryption_key, original_zip = json_data["data"].split(":")
base64_encoded_data.strip()
original_zip.strip()

encrypted_data = base64.b64decode(base64_encoded_data)
decrypt_data = xor_decrypt(encrypted_data, encryption_key)

output_zip_file = f"{original_zip}.zip"
with open(output_zip_file, "wb") as f:
    f.write(decrypt_data)

print(f"Done. Data extracted to {original_zip}.zip")