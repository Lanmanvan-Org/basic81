#!/usr/bin/env python3
"""
Banner Grabber Module
Connect to services and grab banners to identify software versions

Upgraded to support many protocols (best-effort):
 - raw (generic TCP)
 - http, https
 - websocket (ws, wss)
 - ftp, sftp (uses SSH banner)
 - ssh
 - smtp (25), smtps (465), submission (587)
 - pop3, pop3s
 - imap, imaps
 - telnet
 - redis
 - memcached
 - mysql
 - postgresql
 - mongodb
 - elasticsearch
 - rdp
 - vnc
 - dns (UDP)
 - snmp (UDP)
 - ldap
 - nntp
 - mssql
 - cassandra
 - kafka

This is a best-effort banner grabber — many protocols do not send
useful banners without a proper client handshake, so we try lightweight
probes where reasonable and fall back to a raw recv.
"""

import os
import sys
import socket
import ssl
import time
import base64
import random
import struct

try:
    import requests
except Exception:
    requests = None  # used when available


def tcp_connect(host, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    return sock


def recv_all(sock, bufsize=4096):
    try:
        data = sock.recv(bufsize)
        return data.decode('utf-8', errors='ignore').strip()
    except Exception:
        return ""


def grab_raw_banner(host, port, timeout):
    """Generic raw TCP banner grab"""
    try:
        sock = tcp_connect(host, port, timeout)
        banner = recv_all(sock)
        sock.close()
        return banner or "NO_BANNER"
    except socket.timeout:
        return "TIMEOUT"
    except socket.error as e:
        return f"ERROR: {e}"


def grab_http_banner(host, port, timeout, use_https=False, path="/"):
    """HTTP(S) banner via requests (if available) or raw socket HTTP request"""
    try:
        if requests:
            scheme = "https" if use_https else "http"
            url = f"{scheme}://{host}:{port}{path}"
            r = requests.get(url, timeout=timeout, allow_redirects=False, verify=False)
            server = r.headers.get('Server', 'Unknown')
            return f"{r.status_code} {r.reason} | Server: {server}"
        else:
            # Fallback: send a minimal HTTP request over socket (optionally TLS)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            if use_https:
                ctx = ssl.create_default_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)
            req = f"GET /{path.lstrip('/')} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            sock.send(req.encode())
            banner = recv_all(sock)
            sock.close()
            # extract Server header if present
            for line in banner.splitlines():
                if line.lower().startswith("server:"):
                    return line.strip()
            return banner.splitlines()[0] if banner else "NO_BANNER"
    except Exception as e:
        return f"ERROR: {e}"


def grab_websocket_banner(host, port, timeout, use_wss=False, path="/"):
    """Attempt a WebSocket handshake and read server response headers"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        if use_wss:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)

        key = base64.b64encode(bytes([random.getrandbits(8) for _ in range(16)])).decode()
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        sock.send(req.encode())
        resp = recv_all(sock)
        sock.close()
        # return status line + server header if present
        lines = resp.splitlines()
        status = lines[0] if lines else ""
        server = next((l for l in lines if l.lower().startswith("server:")), "")
        return f"{status} {server}".strip()
    except Exception as e:
        return f"ERROR: {e}"


def grab_ftp_banner(host, port, timeout):
    """FTP banner (read initial greeting)"""
    return grab_raw_banner(host, port, timeout)


def grab_ssh_banner(host, port, timeout):
    """SSH sends a version string on connect"""
    return grab_raw_banner(host, port, timeout)


def grab_smtp_banner(host, port, timeout):
    """SMTP banner: read greeting; optionally send EHLO"""
    try:
        sock = tcp_connect(host, port, timeout)
        banner = recv_all(sock)
        # Try a lightweight EHLO to coax a response (some servers only respond after EHLO)
        try:
            sock.send(b"EHLO example.com\r\n")
            time.sleep(0.1)
            resp = recv_all(sock)
            banner = (banner + "\n" + resp).strip()
        except Exception:
            pass
        sock.close()
        return banner or "NO_BANNER"
    except Exception as e:
        return f"ERROR: {e}"


def grab_pop3_banner(host, port, timeout):
    return grab_raw_banner(host, port, timeout)


def grab_imap_banner(host, port, timeout):
    return grab_raw_banner(host, port, timeout)


def grab_redis_banner(host, port, timeout):
    """Send INFO command to Redis (RESP format)"""
    try:
        sock = tcp_connect(host, port, timeout)
        # Send: "*1\r\n$4\r\nINFO\r\n"
        sock.send(b"*1\r\n$4\r\nINFO\r\n")
        time.sleep(0.05)
        banner = recv_all(sock, bufsize=8192)
        sock.close()
        return banner or "NO_BANNER"
    except Exception as e:
        return f"ERROR: {e}"


def grab_memcached_banner(host, port, timeout):
    """Request version from memcached"""
    try:
        sock = tcp_connect(host, port, timeout)
        sock.send(b"version\r\n")
        time.sleep(0.05)
        banner = recv_all(sock)
        sock.close()
        return banner or "NO_BANNER"
    except Exception as e:
        return f"ERROR: {e}"


def grab_mysql_banner(host, port, timeout):
    """MySQL sends an initial handshake packet from server; read it"""
    return grab_raw_banner(host, port, timeout)


def grab_postgres_banner(host, port, timeout):
    """Postgres usually waits for startup packet; attempt to read initial bytes"""
    return grab_raw_banner(host, port, timeout)


def grab_mongo_banner(host, port, timeout):
    """MongoDB may not send on connect; try a raw read"""
    return grab_raw_banner(host, port, timeout)


def grab_elasticsearch_banner(host, port, timeout):
    """Elasticsearch typically speaks HTTP on 9200"""
    return grab_http_banner(host, port, timeout, use_https=False, path="/")


def grab_ldap_banner(host, port, timeout):
    return grab_raw_banner(host, port, timeout)


def grab_nntp_banner(host, port, timeout):
    return grab_raw_banner(host, port, timeout)


def grab_rdp_banner(host, port, timeout):
    return grab_raw_banner(host, port, timeout)


def grab_vnc_banner(host, port, timeout):
    """VNC sends RFB header on connect"""
    return grab_raw_banner(host, port, timeout)


def grab_mssql_banner(host, port, timeout):
    return grab_raw_banner(host, port, timeout)


def grab_cassandra_banner(host, port, timeout):
    return grab_raw_banner(host, port, timeout)


def grab_kafka_banner(host, port, timeout):
    return grab_raw_banner(host, port, timeout)


def grab_dns_banner(host, port, timeout):
    """Send a minimal DNS query (UDP) for 'example.com' A record"""
    try:
        qname = b"example.com"
        # Build a very small DNS query
        def build_query(name):
            parts = name.split(b".")
            body = b"".join(bytes([len(p)]) + p for p in parts) + b"\x00"
            # Header: ID (2), Flags (2), QDCOUNT(2)=1, ANCOUNT(2)=0, NSCOUNT(2)=0, ARCOUNT(2)=0
            header = struct.pack(">HHHHHH", random.randint(0, 0xFFFF), 0x0100, 1, 0, 0, 0)
            # QTYPE A (1), QCLASS IN (1)
            question = body + struct.pack(">HH", 1, 1)
            return header + question

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(build_query(qname), (host, port))
        data, _ = sock.recvfrom(4096)
        sock.close()
        return f"DNS response {len(data)} bytes"
    except socket.timeout:
        return "TIMEOUT"
    except Exception as e:
        return f"ERROR: {e}"


def grab_snmp_banner(host, port, timeout):
    """Attempt a trivial SNMP request (may require community string; best-effort)"""
    try:
        # We'll send an empty-ish UDP packet to provoke some response (best-effort)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"\x30\x00", (host, port))
        data, _ = sock.recvfrom(4096)
        sock.close()
        return f"SNMP response {len(data)} bytes"
    except socket.timeout:
        return "TIMEOUT"
    except Exception as e:
        return f"ERROR: {e}"


# Protocol -> (default_port, grab_function, friendly_name)
PROTOCOL_MAP = {
    "raw": (None, grab_raw_banner, "Raw TCP"),
    "http": (80, grab_http_banner, "HTTP"),
    "https": (443, lambda h, p, t: grab_http_banner(h, p, t, use_https=True), "HTTPS"),
    "websocket": (80, lambda h, p, t: grab_websocket_banner(h, p, t, use_wss=False), "WebSocket"),
    "wss": (443, lambda h, p, t: grab_websocket_banner(h, p, t, use_wss=True), "WebSocket Secure"),
    "ftp": (21, grab_ftp_banner, "FTP"),
    "ssh": (22, grab_ssh_banner, "SSH"),
    "sftp": (22, grab_ssh_banner, "SFTP (SSH)"),
    "smtp": (25, grab_smtp_banner, "SMTP"),
    "smtps": (465, grab_smtp_banner, "SMTPS"),
    "submission": (587, grab_smtp_banner, "SMTP Submission"),
    "pop3": (110, grab_pop3_banner, "POP3"),
    "pop3s": (995, grab_pop3_banner, "POP3S"),
    "imap": (143, grab_imap_banner, "IMAP"),
    "imaps": (993, grab_imap_banner, "IMAPS"),
    "telnet": (23, grab_raw_banner, "Telnet"),
    "redis": (6379, grab_redis_banner, "Redis"),
    "memcached": (11211, grab_memcached_banner, "Memcached"),
    "mysql": (3306, grab_mysql_banner, "MySQL"),
    "postgresql": (5432, grab_postgres_banner, "PostgreSQL"),
    "mongodb": (27017, grab_mongo_banner, "MongoDB"),
    "elasticsearch": (9200, grab_elasticsearch_banner, "Elasticsearch"),
    "ldap": (389, grab_ldap_banner, "LDAP"),
    "nntp": (119, grab_nntp_banner, "NNTP"),
    "rdp": (3389, grab_rdp_banner, "RDP"),
    "vnc": (5900, grab_vnc_banner, "VNC"),
    "mssql": (1433, grab_mssql_banner, "MSSQL"),
    "cassandra": (9042, grab_cassandra_banner, "Cassandra"),
    "kafka": (9092, grab_kafka_banner, "Kafka"),
    "dns": (53, grab_dns_banner, "DNS (UDP)"),
    "snmp": (161, grab_snmp_banner, "SNMP (UDP)"),
}


def identify_software(banner):
    banner_lower = banner.lower()
    identified = []
    # Simple keyword matches for common servers
    if "apache" in banner_lower:
        identified.append("Apache Web Server")
    if "nginx" in banner_lower:
        identified.append("NGINX Web Server")
    if "microsoft" in banner_lower or "iis" in banner_lower:
        identified.append("Microsoft IIS")
    if "openssh" in banner_lower or "ssh-" in banner_lower:
        identified.append("OpenSSH / SSH")
    if "vsftpd" in banner_lower or "ftp" in banner_lower:
        identified.append("FTP Server (vsftpd or other)")
    if "redis" in banner_lower:
        identified.append("Redis")
    if "memcached" in banner_lower:
        identified.append("Memcached")
    if "mysql" in banner_lower or "mariadb" in banner_lower:
        identified.append("MySQL / MariaDB")
    if "postgres" in banner_lower or "pgsql" in banner_lower:
        identified.append("PostgreSQL")
    if "mongodb" in banner_lower:
        identified.append("MongoDB")
    if "elasticsearch" in banner_lower or "elastic" in banner_lower:
        identified.append("Elasticsearch")
    if "smtp" in banner_lower or "esmtp" in banner_lower:
        identified.append("SMTP Mail Server")
    if "imap" in banner_lower:
        identified.append("IMAP Mail Server")
    if "pop3" in banner_lower:
        identified.append("POP3 Mail Server")
    if "http" in banner_lower or "server:" in banner_lower:
        identified.append("HTTP server")
    if "rdp" in banner_lower:
        identified.append("RDP")
    if "vnc" in banner_lower or "rfb" in banner_lower:
        identified.append("VNC")
    if "ldap" in banner_lower:
        identified.append("LDAP")
    if "kafka" in banner_lower:
        identified.append("Kafka")
    # dedupe
    return list(dict.fromkeys(identified))


def main():
    host = os.getenv('ARG_HOST')
    port_env = os.getenv('ARG_PORT')
    timeout = int(os.getenv('ARG_TIMEOUT', '5'))
    protocol = os.getenv('ARG_PROTOCOL', 'raw').lower()

    if not host:
        print("Error: host required")
        sys.exit(1)

    # Determine default port for protocol if not provided
    proto_entry = PROTOCOL_MAP.get(protocol)
    if proto_entry:
        default_port = proto_entry[0]
        grab_fn = proto_entry[1]
        friendly = proto_entry[2]
    else:
        default_port = None
        grab_fn = grab_raw_banner
        friendly = "Raw TCP (unknown protocol)"

    port = int(port_env) if port_env else (default_port or 80)

    print(f"[*] Grabbing banner from {host}:{port}")
    print(f"[*] Protocol: {protocol} ({friendly}), Timeout: {timeout}s")

    try:
        banner = grab_fn(host, port, timeout)
    except TypeError:
        # Support old-style grab_http_banner signature if used from map
        banner = grab_fn(host, port, timeout)

    if isinstance(banner, str) and banner.startswith("ERROR"):
        print(f"[!] {banner}")
        sys.exit(1)

    print(f"\n[+] Banner:")
    # Ensure we have a printable banner
    if not banner:
        banner = "NO_BANNER"
    print(f"    {banner}")

    identified = identify_software(banner)
    if identified:
        for item in identified:
            print(f"[+] Identified: {item}")
    else:
        print("[+] Identified: Unknown / Could not determine")

    print("\n[+] Complete")


if __name__ == "__main__":
    main()
