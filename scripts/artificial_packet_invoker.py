#!/usr/bin/env python3
import argparse
import time
import socket
import threading
import requests
import random
import logging
import sys

# Set up logging format
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def perform_http_traffic(target_ip, count=8):
    """Generates normal HTTP GET and POST requests so the sniffer can extract HTTP flows."""
    logging.info(f"Generating {count} HTTP requests to {target_ip}...")
    urls = [
        f"http://{target_ip}:80/",
        f"http://{target_ip}:80/login",
        f"http://{target_ip}:80/api/data",
        f"http://{target_ip}:80/admin",
        f"http://{target_ip}:8080/",
    ]
    
    for i in range(count):
        url = random.choice(urls)
        try:
            if random.choice([True, False]):
                 requests.get(url, timeout=1)
            else:
                 requests.post(url, data={'user': 'test', 'pass': 'test'}, timeout=1)
        except requests.RequestException:
            # We don't care if the server doesn't respond, we just want the packets on the wire
            pass
        time.sleep(0.5)
    logging.info("HTTP traffic generation complete.")

def perform_stealth_syn_scan(target_ip, ports_to_scan=10, start_port=2000):
    """
    Simulates a port scan by sending pure TCP SYN packets using scapy.
    Fallback to standard socket connect() if scapy is not available. 
    packet_sniffer.py expects >= 5 SYN packets to different ports to trigger anomalies.
    """
    logging.info(f"Generating port scan (SYN packets) to {ports_to_scan} ports on {target_ip}...")
    try:
        from scapy.all import IP, TCP, send
        use_scapy = True
    except ImportError:
        logging.warning("Scapy not found. Falling back to standard socket connect() for port scan generation.")
        use_scapy = False

    if use_scapy:
        for i in range(ports_to_scan):
            dst_port = start_port + i
            # Construct a pure SYN packet (Flags="S")
            pkt = IP(dst=target_ip) / TCP(dport=dst_port, flags="S", sport=random.randint(1024, 65535))
            send(pkt, verbose=False)
            time.sleep(0.1)
    else:
        for i in range(ports_to_scan):
            dst_port = start_port + i
            # A standard socket connect will initially transmit a SYN
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            try:
                s.connect((target_ip, dst_port))
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass
            finally:
                s.close()
    
    logging.info("Port scan generation complete.")

def perform_fragmentation_attack(target_ip):
    """Simulates fragmented IP packets, requiring Scapy."""
    logging.info(f"Generating fragmented IP packets to {target_ip}...")
    try:
        from scapy.all import IP, ICMP, fragment, send
        # Create a large ICMP packet and fragment it into small chunks
        pkt = IP(dst=target_ip)/ICMP()/("X"*1000)
        frags = fragment(pkt, fragsize=200)
        for frag in frags:
            send(frag, verbose=False)
            time.sleep(0.05)
        logging.info("Fragmentation attack generation complete.")
    except ImportError:
        logging.error("Scapy is required for generating fragmented packets. Skipping.")

def perform_web_attack(target_ip):
    """Simulates malicious web attack requests like cleartext transmission/SQLi in HTTP."""
    logging.info(f"Generating web attack traffic to {target_ip}...")
    
    # Anomaly 1: Cleartext passwords in URL
    url = f"http://{target_ip}:80/login?password=mysecretpassword&username=admin"
    try:
        requests.get(url, timeout=1)
    except requests.RequestException:
        pass
    
    # Anomaly 2: Simple SQLi string in URI
    sqli_url = f"http://{target_ip}:80/items?id=1%20OR%201=1"
    try:
        requests.get(sqli_url, timeout=1)
    except requests.RequestException:
        pass
    
    logging.info("Web attack generation complete.")

def main():
    parser = argparse.ArgumentParser(description="Artificial Packet Invoker Tool - For testing NetShieldAI packet_sniffer.py")
    parser.add_argument("--target", "-t", required=True, help="Target IP address to send packets towards (e.g., 127.0.0.1 or an external IP)")
    parser.add_argument("--all", "-A", action="store_true", help="Run all attack and traffic simulations")
    parser.add_argument("--http", action="store_true", help="Generate normal HTTP flows (GET/POST)")
    parser.add_argument("--scan", action="store_true", help="Generate a port scan (SYN packets) to trigger port scan anomaly (>= 5 ports)")
    parser.add_argument("--frag", action="store_true", help="Generate fragmented packets (Requires Scapy)")
    parser.add_argument("--web", action="store_true", help="Generate malicious web requests (Cleartext, SQLi)")

    args = parser.parse_args()

    # If no specific flags are provided and --all is not set, default to just http and scan
    if not any([args.all, args.http, args.scan, args.frag, args.web]):
        logging.info("No explicit traffic flags provided. Defaulting to --http and --scan.")
        args.http = True
        args.scan = True

    try:
        socket.inet_aton(args.target)
    except socket.error:
        logging.error(f"Invalid target IP format: {args.target}")
        sys.exit(1)

    logging.info(f"Starting simulated traffic generation against target: {args.target}")

    threads = []
    
    if args.all or args.http:
        t = threading.Thread(target=perform_http_traffic, args=(args.target,))
        threads.append(t)
        t.start()

    if args.all or args.scan:
        t = threading.Thread(target=perform_stealth_syn_scan, args=(args.target,))
        threads.append(t)
        t.start()
        
    if args.all or args.frag:
         t = threading.Thread(target=perform_fragmentation_attack, args=(args.target,))
         threads.append(t)
         t.start()

    if args.all or args.web:
         t = threading.Thread(target=perform_web_attack, args=(args.target,))
         threads.append(t)
         t.start()

    for t in threads:
        t.join()

    logging.info("All selected packet generation simulations have successfully completed.")

if __name__ == "__main__":
    main()
