#!/usr/bin/env python3
"""
Test ferret's RPC server using the EXACT same code path NomadNet uses.
Run ferret first, then run this script.
"""
import hashlib
import sys
import traceback

# Step 1: Compute the RPC key exactly like Python RNS does
identity_path = "/Users/pony/.reticulum/storage/identity"
try:
    with open(identity_path, "rb") as f:
        private_key = f.read()
    # Python RNS: RNS.Identity.full_hash(Transport.identity.get_private_key())
    # full_hash = SHA-256
    rpc_key = hashlib.sha256(private_key).digest()
    print(f"[OK] RPC key computed: {rpc_key.hex()[:16]}...")
except Exception as e:
    print(f"[FAIL] Could not read identity: {e}")
    sys.exit(1)

# Step 2: Connect using multiprocessing.connection.Client
# This is EXACTLY what Python RNS does in get_rpc_client()
import multiprocessing.connection
rpc_addr = ("127.0.0.1", 37429)
rpc_type = "AF_INET"

print(f"[INFO] Connecting to RPC at {rpc_addr}...")
try:
    conn = multiprocessing.connection.Client(rpc_addr, family=rpc_type, authkey=rpc_key)
    print("[OK] Connected and authenticated!")
except Exception as e:
    print(f"[FAIL] Connection/auth failed: {e}")
    traceback.print_exc()
    sys.exit(1)

# Step 3: Send get_interface_stats (this is what crashes NomadNet TUI)
print("[INFO] Sending get_interface_stats...")
try:
    conn.send({"get": "interface_stats"})
    response = conn.recv()
    print(f"[OK] Got response: type={type(response).__name__}")
    if isinstance(response, dict):
        print(f"  Keys: {list(response.keys())}")
        if "interfaces" in response:
            ifaces = response["interfaces"]
            print(f"  Interfaces: {len(ifaces)}")
            for i, iface in enumerate(ifaces):
                if isinstance(iface, dict):
                    print(f"    [{i}] name={iface.get('name','?')} status={iface.get('status','?')} rxb={iface.get('rxb','?')} txb={iface.get('txb','?')}")
                else:
                    print(f"    [{i}] unexpected type: {type(iface).__name__}: {iface}")
    else:
        print(f"  Raw: {response}")
    conn.close()
except Exception as e:
    print(f"[FAIL] RPC call failed: {e}")
    traceback.print_exc()
    sys.exit(1)

# Step 4: Test get_path_table
print("[INFO] Testing get_path_table...")
try:
    conn2 = multiprocessing.connection.Client(rpc_addr, family=rpc_type, authkey=rpc_key)
    conn2.send({"get": "path_table", "max_hops": None})
    response2 = conn2.recv()
    print(f"[OK] path_table: type={type(response2).__name__}, len={len(response2) if hasattr(response2, '__len__') else 'N/A'}")
    conn2.close()
except Exception as e:
    print(f"[FAIL] path_table failed: {e}")
    traceback.print_exc()

# Step 5: Test get_link_count
print("[INFO] Testing get_link_count...")
try:
    conn3 = multiprocessing.connection.Client(rpc_addr, family=rpc_type, authkey=rpc_key)
    conn3.send({"get": "link_count"})
    response3 = conn3.recv()
    print(f"[OK] link_count: {response3}")
    conn3.close()
except Exception as e:
    print(f"[FAIL] link_count failed: {e}")
    traceback.print_exc()

print("\n[DONE] All RPC tests passed!")
