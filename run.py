"""Start Firesharing on your local network for internal team access.

Usage:
    python run.py

This binds to 0.0.0.0:5000 so anyone on your network can reach it
at http://YOUR_IP:5000.
"""

import socket
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from config import Config


def get_local_ips():
    """Return all non-loopback IPv4 addresses for this machine."""
    ips = []
    try:
        hostname = socket.gethostname()
        ips.append(socket.gethostbyname(hostname))
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(('10.255.255.255', 1))
        ips.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        for iface in socket.getaddrinfo(hostname, None):
            addr = iface[4][0]
            if addr not in ips and not addr.startswith('127.'):
                ips.append(addr)
    except Exception:
        pass
    return list(dict.fromkeys(ips))


def main():
    app = create_app()

    for d in [Config.UPLOAD_FOLDER, Config.KEY_FOLDER, Config.DOWNLOAD_FOLDER]:
        os.makedirs(d, exist_ok=True)

    host = Config.SERVER_HOST
    port = Config.SERVER_PORT
    local_ips = get_local_ips()

    print('=' * 58)
    print('  Firesharing — Encrypted File Sharing')
    print('=' * 58)
    print()
    print(f'  Server  : {host}:{port}')
    print()
    print('  Share this URL with internal team members:')
    for ip in local_ips:
        print(f'    -> http://{ip}:{port}')
    print()
    if not local_ips:
        print('  (no local IP detected; check your network connection)')
        print()
    print('  Press Ctrl+C to stop the server.')
    print('=' * 58)
    print()

    # Disable reloader so we only print the banner once
    app.run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == '__main__':
    main()
