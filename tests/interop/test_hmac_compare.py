#!/usr/bin/env python3
"""Compare HMAC computation between Python and what ferret should produce."""
import hmac, hashlib

key = b"testkey"
message = b"{sha256}hello world 1234567890 abcdefghij"

# Python's computation (what _verify_challenge does)
expected = hmac.new(key, message, 'sha256').digest()
print(f"Python HMAC: {expected.hex()}")

# What ferret computes: hmac_sha256(key, message) 
# This should be identical since both use HMAC-SHA256
# Let's verify with the raw hmac module
raw = hmac.new(key, message, hashlib.sha256).digest()
print(f"Raw HMAC:    {raw.hex()}")
print(f"Match: {expected == raw}")

# Now test with the actual RPC key
identity_path = "/Users/pony/.reticulum/storage/identity"
with open(identity_path, "rb") as f:
    private_key = f.read()
rpc_key = hashlib.sha256(private_key).digest()

test_msg = b"{sha256}" + b"A" * 40
py_mac = hmac.new(rpc_key, test_msg, 'sha256').digest()
print(f"\nWith real RPC key:")
print(f"  Key: {rpc_key.hex()[:16]}...")
print(f"  Message: {test_msg[:20]}... ({len(test_msg)} bytes)")
print(f"  HMAC: {py_mac.hex()}")
