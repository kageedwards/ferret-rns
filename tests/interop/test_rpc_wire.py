#!/usr/bin/env python3
"""Test ferret's RPC server with a real Python multiprocessing.connection Client."""
import multiprocessing.connection as mc
import hashlib, sys, time

# Ferret's RPC port
RPC_PORT = 37429

# Compute the RPC key the same way ferret does: SHA-256(private_key)
# Read the identity file
identity_path = "/Users/pony/.reticulum/storage/identity"
try:
    with open(identity_path, "rb") as f:
        private_key = f.read()
    rpc_key = hashlib.sha256(private_key).digest()
    print(f"RPC key: {rpc_key.hex()[:16]}...")
except Exception as e:
    print(f"Could not read identity: {e}")
    sys.exit(1)

# Connect using Python's multiprocessing.connection.Client
print(f"Connecting to 127.0.0.1:{RPC_PORT}...")
try:
    conn = mc.Client(("127.0.0.1", RPC_PORT), family="AF_INET", authkey=rpc_key)
    print("Connected and authenticated!")
    
    # Send get_interface_stats command
    conn.send({"get": "interface_stats"})
    response = conn.recv()
    print(f"interface_stats response type: {type(response)}")
    if isinstance(response, dict):
        print(f"Keys: {list(response.keys())}")
        if "interfaces" in response:
            print(f"Number of interfaces: {len(response['interfaces'])}")
            for iface in response["interfaces"]:
                print(f"  - {iface.get('name', 'unknown')}: online={iface.get('status', '?')}")
    else:
        print(f"Response: {response}")
    
    conn.close()
    print("Done!")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
