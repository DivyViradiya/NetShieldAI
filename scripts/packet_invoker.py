#!/usr/bin/env python3
"""
NetShieldAI Packet Invoker
-------------------------
A multi-protocol packet generator and receiver tool designed to test the NetShieldAI
packet sniffer and anomaly detection services.

Modes of operation:
  - send:     Sends TCP or UDP packets to a remote host and fetches any response.
  - listen:   Binds to a port and fetches (receives) incoming TCP or UDP packets.
  - loopback: Performs a self-contained local loopback test by spawning a listener thread
              and sending packets to it, verifying flow.
"""

import sys
import time
import socket
import argparse
import threading
import random
import logging

# Configure logging with a professional style
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("PacketInvoker")

# Sample payloads representing different traffic types
PAYLOADS = {
    "hello": "Hello NetShieldAI Packet Sniffer! This is a test message.",
    "http_get": "GET /index.html HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: PacketInvoker/1.0\r\n\r\n",
    "http_post": "POST /login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 27\r\n\r\nusername=admin&password=123",
    "dns_query": "\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01",
    "random": None # Generated dynamically
}

def get_payload(payload_type, size=64):
    if payload_type == "random":
        # Generate random printable characters
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
        return "".join(random.choice(chars) for _ in range(size))
    return PAYLOADS.get(payload_type, PAYLOADS["hello"])

def send_tcp(target_ip, port, payload_type, count, delay, timeout, size=64, stop_event=None):
    logger.info(f"🚀 Initializing TCP Sender -> target: {target_ip}:{port}")
    payload = get_payload(payload_type, size)
    
    i = 0
    while (count <= 0 or i < count) and not (stop_event and stop_event.is_set()):
        iter_str = f"{i+1}" if count <= 0 else f"{i+1}/{count}"
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            logger.info(f"[{iter_str}] Connecting to {target_ip}:{port}...")
            s.connect((target_ip, port))
            
            # Send payload
            data = payload.encode('utf-8') if isinstance(payload, str) else payload
            logger.info(f"[{iter_str}] Sending {len(data)} bytes TCP payload...")
            s.sendall(data)
            
            # Read (fetch) response
            try:
                response = s.recv(4096)
                logger.info(f"[{iter_str}] Fetched TCP response: {response!r}")
            except socket.timeout:
                logger.debug(f"[{iter_str}] Timeout waiting for response.")
        except Exception as e:
            if not (stop_event and stop_event.is_set()):
                logger.error(f"[!] TCP Error on transmit {i+1}: {e}")
        finally:
            if s:
                s.close()
        
        i += 1
        if (count <= 0 or i < count) and not (stop_event and stop_event.is_set()):
            # Sleep in small steps to be highly responsive to interruption
            sleep_remaining = delay
            while sleep_remaining > 0 and not (stop_event and stop_event.is_set()):
                time.sleep(min(0.1, sleep_remaining))
                sleep_remaining -= 0.1
            
    logger.info("✅ TCP Send sequence completed.")

def send_udp(target_ip, port, payload_type, count, delay, timeout, size=64, stop_event=None):
    logger.info(f"🚀 Initializing UDP Sender -> target: {target_ip}:{port}")
    payload = get_payload(payload_type, size)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    
    i = 0
    try:
        while (count <= 0 or i < count) and not (stop_event and stop_event.is_set()):
            iter_str = f"{i+1}" if count <= 0 else f"{i+1}/{count}"
            try:
                data = payload.encode('utf-8') if isinstance(payload, str) else payload
                logger.info(f"[{iter_str}] Sending {len(data)} bytes UDP datagram...")
                s.sendto(data, (target_ip, port))
                
                # Fetch optional response (UDP reply)
                try:
                    response, addr = s.recvfrom(4096)
                    logger.info(f"[{iter_str}] Fetched UDP response from {addr}: {response!r}")
                except socket.timeout:
                    pass
            except Exception as e:
                if not (stop_event and stop_event.is_set()):
                    logger.error(f"[!] UDP Error on transmit {i+1}: {e}")
            
            i += 1
            if (count <= 0 or i < count) and not (stop_event and stop_event.is_set()):
                # Sleep in small steps to be highly responsive to interruption
                sleep_remaining = delay
                while sleep_remaining > 0 and not (stop_event and stop_event.is_set()):
                    time.sleep(min(0.1, sleep_remaining))
                    sleep_remaining -= 0.1
    finally:
        s.close()
        
    logger.info("✅ UDP Send sequence completed.")

def listen_tcp(bind_ip, port, stop_event, echo_response=True):
    logger.info(f"📡 TCP Listener binding to {bind_ip}:{port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        s.bind((bind_ip, port))
        s.listen(5)
        s.settimeout(0.5) # Short timeout to keep check responsive
        logger.info(f"📡 TCP Listener active on {bind_ip}:{port}. Awaiting connections...")
        
        while not stop_event.is_set():
            try:
                conn, addr = s.accept()
                logger.info(f"[+] Accepted connection from {addr[0]}:{addr[1]}")
                conn.settimeout(1.5)
                
                try:
                    data = conn.recv(4096)
                    if data:
                        logger.info(f"[+] Fetched {len(data)} bytes: {data!r}")
                        if echo_response:
                            conn.sendall(b"ACK: Received. " + data[:100])
                except Exception as read_err:
                    logger.error(f"[!] TCP read error: {read_err}")
                finally:
                    conn.close()
            except socket.timeout:
                continue
            except Exception as accept_err:
                if not stop_event.is_set():
                    logger.error(f"[!] TCP accept exception: {accept_err}")
    except Exception as bind_err:
        logger.error(f"[!] Failed to bind TCP listener: {bind_err}")
    finally:
        s.close()
        logger.info("📡 TCP Listener shut down.")

def listen_udp(bind_ip, port, stop_event, echo_response=True):
    logger.info(f"📡 UDP Listener binding to {bind_ip}:{port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        s.bind((bind_ip, port))
        s.settimeout(0.5)
        logger.info(f"📡 UDP Listener active on {bind_ip}:{port}. Awaiting datagrams...")
        
        while not stop_event.is_set():
            try:
                data, addr = s.recvfrom(4096)
                logger.info(f"[+] Received UDP datagram from {addr[0]}:{addr[1]}: {data!r}")
                if echo_response:
                    s.sendto(b"ACK: Received. " + data[:100], addr)
            except socket.timeout:
                continue
            except Exception as recv_err:
                if not stop_event.is_set():
                    logger.error(f"[!] UDP receive exception: {recv_err}")
    except Exception as bind_err:
        logger.error(f"[!] Failed to bind UDP listener: {bind_err}")
    finally:
        s.close()
        logger.info("📡 UDP Listener shut down.")

def run_loopback_test(proto, bind_ip, port, payload_type, count, delay, timeout, size=64):
    logger.info(f"🔄 Starting loopback testing sequence (Protocol: {proto.upper()})")
    stop_event = threading.Event()
    threads = []
    
    # 1. Start listeners
    if proto in ("tcp", "both"):
        t_tcp = threading.Thread(target=listen_tcp, args=(bind_ip, port, stop_event, True))
        t_tcp.daemon = True
        threads.append(t_tcp)
        t_tcp.start()
        
    if proto in ("udp", "both"):
        udp_port = port + 1 if proto == "both" else port
        t_udp = threading.Thread(target=listen_udp, args=(bind_ip, udp_port, stop_event, True))
        t_udp.daemon = True
        threads.append(t_udp)
        t_udp.start()
        
    # Wait for listeners to bind
    time.sleep(0.5)
    
    # 2. Run client senders in threads as well, so both TCP and UDP can run concurrently
    client_target = "127.0.0.1" if bind_ip == "0.0.0.0" else bind_ip
    client_threads = []
    
    if proto in ("tcp", "both"):
        t_send_tcp = threading.Thread(
            target=send_tcp,
            args=(client_target, port, payload_type, count, delay, timeout, size, stop_event)
        )
        t_send_tcp.daemon = True
        client_threads.append(t_send_tcp)
        t_send_tcp.start()
        
    if proto in ("udp", "both"):
        udp_port = port + 1 if proto == "both" else port
        t_send_udp = threading.Thread(
            target=send_udp,
            args=(client_target, udp_port, payload_type, count, delay, timeout, size, stop_event)
        )
        t_send_udp.daemon = True
        client_threads.append(t_send_udp)
        t_send_udp.start()
        
    try:
        # Keep main thread alive/waiting for client senders or KeyboardInterrupt
        while any(t.is_alive() for t in client_threads):
            time.sleep(0.1)
    except KeyboardInterrupt:
        logger.info("\n[!] Execution interrupted by user (Ctrl+C).")
    finally:
        # 3. Clean shutdown of background threads
        logger.info("[*] Cleaning up background listeners and senders...")
        stop_event.set()
        for t in threads + client_threads:
            t.join(timeout=2.0)
        logger.info("🔄 Loopback test completed.")

def main():
    parser = argparse.ArgumentParser(
        description="NetShieldAI Packet Invoker - TCP/UDP generator and receiver for sniffer verification."
    )
    parser.add_argument(
        "--mode", "-m", choices=["send", "listen", "loopback"], required=True,
        help="Operating mode: send (client), listen (server), or loopback (both)."
    )
    parser.add_argument(
        "--proto", "-p", choices=["tcp", "udp", "both"], default="both",
        help="Protocol to target (default: both)."
    )
    parser.add_argument(
        "--target", "-t", default="127.0.0.1",
        help="Target IP address for send mode (default: 127.0.0.1)."
    )
    parser.add_argument(
        "--port", "-P", type=int, default=8888,
        help="Destination port or base port for bindings (default: 8888)."
    )
    parser.add_argument(
        "--bind-ip", "-b", default="0.0.0.0",
        help="IP address to bind the listener to (default: 0.0.0.0)."
    )
    parser.add_argument(
        "--payload", choices=list(PAYLOADS.keys()), default="hello",
        help="Predefined payload pattern to transmit (default: hello)."
    )
    parser.add_argument(
        "--size", type=int, default=64,
        help="Size of random payload to generate if payload is 'random' (default: 64)."
    )
    parser.add_argument(
        "--count", "-c", type=int, default=5,
        help="Number of packets to send (default: 5). Use 0 or -1 for continuous."
    )
    parser.add_argument(
        "--continuous", "-C", action="store_true",
        help="Run continuously until interrupted (Ctrl+C). Overrides --count."
    )
    parser.add_argument(
        "--delay", "-d", type=float, default=0.5,
        help="Delay in seconds between packet sends (default: 0.5)."
    )
    parser.add_argument(
        "--timeout", type=float, default=2.0,
        help="Socket timeout limit in seconds (default: 2.0)."
    )
    parser.add_argument(
        "--no-echo", action="store_true",
        help="Disable echo response in listen/loopback modes."
    )

    args = parser.parse_args()

    # Validate target IP
    try:
        socket.inet_aton(args.target)
    except socket.error:
        logger.error(f"[!] Invalid IP address format: {args.target}")
        sys.exit(1)

    # Determine execution count (0 represents continuous mode)
    exec_count = 0 if args.continuous else args.count

    if args.mode == "send":
        client_threads = []
        stop_send_event = threading.Event()
        
        if args.proto in ("tcp", "both"):
            t_tcp = threading.Thread(
                target=send_tcp,
                args=(args.target, args.port, args.payload, exec_count, args.delay, args.timeout, args.size, stop_send_event)
            )
            t_tcp.daemon = True
            client_threads.append(t_tcp)
            
        if args.proto in ("udp", "both"):
            # For send, if "both", send UDP to port + 1
            udp_port = args.port + 1 if args.proto == "both" else args.port
            t_udp = threading.Thread(
                target=send_udp,
                args=(args.target, udp_port, args.payload, exec_count, args.delay, args.timeout, args.size, stop_send_event)
            )
            t_udp.daemon = True
            client_threads.append(t_udp)
            
        for t in client_threads:
            t.start()
            
        try:
            while any(t.is_alive() for t in client_threads):
                time.sleep(0.1)
        except KeyboardInterrupt:
            logger.info("\n[*] Sender interrupted by user (Ctrl+C). Stopping...")
        finally:
            stop_send_event.set()
            for t in client_threads:
                t.join(timeout=2.0)

    elif args.mode == "listen":
        stop_event = threading.Event()
        threads = []
        try:
            if args.proto in ("tcp", "both"):
                t_tcp = threading.Thread(target=listen_tcp, args=(args.bind_ip, args.port, stop_event, not args.no_echo))
                threads.append(t_tcp)
                t_tcp.start()
            if args.proto in ("udp", "both"):
                udp_port = args.port + 1 if args.proto == "both" else args.port
                t_udp = threading.Thread(target=listen_udp, args=(args.bind_ip, udp_port, stop_event, not args.no_echo))
                threads.append(t_udp)
                t_udp.start()
                
            # Block main thread until KeyboardInterrupt
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            logger.info("\n[*] Listener shut down requested by keyboard event (Ctrl+C).")
        finally:
            stop_event.set()
            for t in threads:
                t.join(timeout=2.0)

    elif args.mode == "loopback":
        run_loopback_test(
            args.proto, args.bind_ip, args.port, args.payload,
            exec_count, args.delay, args.timeout, args.size
        )

if __name__ == "__main__":
    main()
