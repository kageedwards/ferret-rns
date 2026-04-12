#!/usr/bin/env python3
"""Check what RPC key the Python RNS client actually uses."""
import hashlib, sys, os
sys.path.insert(0, os.path.expanduser("~/.venv/lib/python3.14/site-packages"))
import RNS

# Create Reticulum instance (connects to ferret)
reticulum = RNS.Reticulum()

# What key does the Python client use?
print(f"rpc_key: {reticulum.rpc_key.hex()[:32]}...")
print(f"rpc_key length: {len(reticulum.rpc_key)}")

# What's the transport identity?
transport_priv = RNS.Transport.identity.get_private_key()
print(f"Transport private key length: {len(transport_priv)}")
print(f"Transport private key: {transport_priv.hex()[:32]}...")

# Compute what the key SHOULD be
expected_key = hashlib.sha256(transport_priv).digest()
print(f"Expected RPC key (SHA256 of transport priv): {expected_key.hex()[:32]}...")
print(f"Keys match: {reticulum.rpc_key == expected_key}")

# Also read the identity file directly
identity_path = os.path.expanduser("~/.reticulum/storage/identity")
with open(identity_path, "rb") as f:
    file_priv = f.read()
file_key = hashlib.sha256(file_priv).digest()
print(f"\nIdentity file private key: {file_priv.hex()[:32]}...")
print(f"File-based RPC key: {file_key.hex()[:32]}...")
print(f"File key matches RNS key: {file_key == reticulum.rpc_key}")
print(f"File priv matches Transport priv: {file_priv == transport_priv}")
