#!/usr/bin/env python3
"""
Simulate exactly what NomadNet does when connecting to ferret.
This replicates the NomadNet startup sequence step by step.
"""
import sys, os, time, traceback

# Use the same config as the real NomadNet
os.environ.setdefault("HOME", os.path.expanduser("~"))

print("Step 1: Import RNS...")
try:
    import RNS
    print(f"  RNS version: {RNS.__version__}")
except Exception as e:
    print(f"  FAIL: {e}")
    sys.exit(1)

print("Step 2: Create Reticulum instance (connects to ferret shared instance)...")
try:
    reticulum = RNS.Reticulum()
    print(f"  Connected: shared={reticulum.is_shared_instance}, client={reticulum.is_connected_to_shared_instance}, standalone={reticulum.is_standalone_instance}")
except Exception as e:
    print(f"  FAIL: {e}")
    traceback.print_exc()
    sys.exit(1)

print("Step 3: Test get_interface_stats (this is what crashes NomadNet TUI)...")
try:
    stats = reticulum.get_interface_stats()
    print(f"  Got stats: type={type(stats).__name__}")
    if isinstance(stats, dict) and "interfaces" in stats:
        print(f"  Interfaces: {len(stats['interfaces'])}")
        for iface in stats['interfaces']:
            print(f"    - {iface.get('name', '?')}: {iface.get('status', '?')}")
    else:
        print(f"  Raw: {stats}")
except Exception as e:
    print(f"  FAIL: {e}")
    traceback.print_exc()

print("Step 4: Test get_path_table...")
try:
    paths = reticulum.get_path_table()
    print(f"  Got {len(paths)} path entries")
except Exception as e:
    print(f"  FAIL: {e}")
    traceback.print_exc()

print("Step 5: Create an Identity...")
try:
    identity = RNS.Identity()
    print(f"  Identity: {identity}")
except Exception as e:
    print(f"  FAIL: {e}")
    traceback.print_exc()

print("Step 6: Create a Destination and announce...")
try:
    dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, "ferrettest", "sim")
    print(f"  Destination: {RNS.prettyhexrep(dest.hash)}")
    dest.announce()
    print(f"  Announced!")
except Exception as e:
    print(f"  FAIL: {e}")
    traceback.print_exc()

print("Step 7: Wait 5 seconds for network activity...")
time.sleep(5)

print("Step 8: Check path table again...")
try:
    paths = reticulum.get_path_table()
    print(f"  Got {len(paths)} path entries")
except Exception as e:
    print(f"  FAIL: {e}")
    traceback.print_exc()

print("\n[DONE] All steps completed successfully!")
reticulum.exit_handler()
