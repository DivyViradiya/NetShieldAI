import subprocess
import datetime
import os
import sys
import time

# --- Configuration ---
# Restoring your full network range for continuous scanning.
NETWORK_RANGE = "192.168.29.48/24"
OUTPUT_DIR = "scan_results"
# Set a timeout in seconds (e.g., 15 minutes). Nmap might be stopped if it takes longer.
SCAN_TIMEOUT = 300 
# Time to wait between scans, in seconds. 15 minutes = 900 seconds.
WAIT_INTERVAL = 300

# --- Main Script ---
def run_scan():
    """
    Runs an Nmap scan and saves the output to a timestamped XML file.
    Streams Nmap's output to the console for real-time progress.
    """
    print(f"--- Starting network scan for {NETWORK_RANGE} ---")
    print(f"Timeout is set to {SCAN_TIMEOUT} seconds.")
    
    # Ensure the output directory exists
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    # Create a unique, timestamped filename for the scan results
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_filename = os.path.join(OUTPUT_DIR, f"scan_{timestamp}.xml")

    # The Nmap command we want to run
    # -sV: Probe open ports to determine service/version info
    # -oX: Output in XML format to the specified file
    command = [
        "nmap",
        "-sV",
        "-oX",
        output_filename,
        NETWORK_RANGE
    ]
    
    # Add 'sudo' to the command if we are not on Windows, as it can speed up scans.
    if os.name != 'nt':
        command.insert(0, 'sudo')
        print("Running with 'sudo'. You may be prompted for your password.")


    try:
        print(f"\nRunning command: {' '.join(command)}\n")
        process = subprocess.run(command, check=True, timeout=SCAN_TIMEOUT)
        print(f"\n✅ Scan successful! Results saved to: {output_filename}")
        return True # Indicate success
    except FileNotFoundError:
        print("❌ Error: 'nmap' (or 'sudo') command not found.")
        print("Please ensure Nmap is installed and in your system's PATH.")
        return False # Indicate failure
    except subprocess.TimeoutExpired:
        print(f"\n❌ Error: Scan timed out after {SCAN_TIMEOUT} seconds.")
        print("The network might be very large or unresponsive. Try increasing the timeout or scanning a smaller range.")
        return False # Indicate failure
    except subprocess.CalledProcessError as e:
        print(f"❌ Error during Nmap scan. Return code: {e.returncode}")
        return False # Indicate failure

if __name__ == "__main__":
    # --- KEY CHANGE: Continuous Loop ---
    # This loop will run forever until you stop the script manually (Ctrl+C).
    while True:
        run_scan()
        
        # Wait for the specified interval before the next scan
        print(f"\n--- Scan complete. Waiting for {WAIT_INTERVAL / 60:.0f} minutes... ---")
        next_scan_time = datetime.datetime.now() + datetime.timedelta(seconds=WAIT_INTERVAL)
        print(f"Next scan will start at approximately: {next_scan_time.strftime('%H:%M:%S')}")
        
        try:
            time.sleep(WAIT_INTERVAL)
        except KeyboardInterrupt:
            print("\nExiting script. Goodbye!")
            sys.exit(0)

