import platform
import subprocess
import os
import sys
import ctypes
import time
from scapy.all import IP, ICMP, sr1, conf

# Define the target IP for testing
# NOTE: Replace this with an IP address on your local network (e.g., your router or another PC).
TARGET_IP = "192.168.29.48" 

def is_admin():
    """Checks if the script is running with administrative/root privileges."""
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    else: # Linux/macOS
        return os.geteuid() == 0

def ensure_admin_privileges():
    """Checks for admin privileges and attempts to re-launch the script with elevation."""
    if is_admin():
        return True

    # If not admin, attempt to re-launch with privileges (Windows specific)
    print("[INFO] Administrator privileges not found. Requesting elevation...")
    
    if platform.system() == "Windows":
        try:
            # Re-launch with the 'runas' verb to trigger the UAC prompt
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            sys.exit(0) # Exit the original non-elevated script
        except Exception as e:
            print(f"[ERROR] Failed to re-launch with admin rights: {e}")
            return False
    
    # Simple fallback for non-Windows systems if elevation logic isn't fully implemented
    return False

def run_scapy_test(target_ip):
    """
    Crafts and sends a custom ICMP Echo Request (ping) packet to the target IP.
    """
    
    print("---------------------------------------------")
    print(f"[*] Starting custom packet craft test to {target_ip}...")
    
    # --- 1. Craft the Packet ---
    # IP() sets the Network Layer (Layer 3) header
    # ICMP() sets the Application/Control Layer payload (Type 8 for Echo Request)
    packet = IP(dst=target_ip) / ICMP()
    
    print(f"[*] Crafted Packet Summary: {packet.summary()}")

    # --- 2. Send and Receive ---
    # sr1 sends the packet and waits for only the first reply (Timeout is 2 seconds)
    # verbose=0 suppresses Scapy's default output for cleaner test results
    
    # Must use sudo on Linux/macOS or run as Administrator on Windows
    conf.verb = 0 # Set Scapy to be quiet
    
    try:
        start_time = time.time()
        # Use sr1 to send and receive one packet
        response = sr1(packet, timeout=2)
        end_time = time.time()

        # --- 3. Analyze the Response ---
        if response:
            print("\n[SUCCESS] Target is LIVE and RESPONDED!")
            print(f"  -> Response received from: {response.src}")
            print(f"  -> Time taken: {(end_time - start_time) * 1000:.2f} ms")
            print(f"  -> Response Summary: {response.summary()}")
            return True
        else:
            print("\n[FAILURE] No response received within the timeout.")
            print("  -> Target may be down, or a firewall is blocking ICMP traffic.")
            return False

    except Exception as e:
        print(f"\n[CRITICAL ERROR] Failed during packet transmission: {e}")
        return False


if __name__ == "__main__":
    # Ensure elevated privileges are available, as Scapy requires them for raw socket access.
    if not ensure_admin_privileges():
        print("[CRITICAL] Cannot run test without Administrator privileges.")
        sys.exit(1)

    print("=============================================")
    print("=          SCAPY PACKET CRAFTING TEST       =")
    print("=============================================")
    
    # Run the test
    test_passed = run_scapy_test(TARGET_IP)
    
    # Final cleanup message
    print("\n=============================================")
    print(f"TEST RESULT: {'PASS' if test_passed else 'FAIL'}")
    print("Test finished.")
    
    # --- ADDED PAUSE ---
    # This line prevents the console window from closing immediately after execution finishes.
    input("Press Enter to exit the elevated command prompt...") 
    # -------------
