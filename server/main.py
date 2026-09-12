"""
Person 1 — entry point.

Run with:
    py -m server.main

First run generates a host key (ssh_host_key) next to this file if one
doesn't already exist.
"""

import asyncio
import os
import asyncssh

from server.ssh_server import HoneypotSSHServer, handle_client
from server import db

HOST = ""          # listen on all interfaces
PORT = 2222         # unprivileged port, no admin/root needed
HOST_KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ssh_host_key")


def ensure_host_key(path: str) -> None:
    if not os.path.exists(path):
        print(f"[*] No host key found at {path}, generating one...")
        key = asyncssh.generate_private_key("ssh-rsa")
        key.write_private_key(path)


async def run() -> None:
    ensure_host_key(HOST_KEY_PATH)
    await db.init_db()

    await asyncssh.create_server(
        HoneypotSSHServer,
        host=HOST,
        port=PORT,
        server_host_keys=[HOST_KEY_PATH],
        process_factory=handle_client,
    )

    print(f"[*] Honeypot listening on port {PORT}")
    print(f"[*] Test with: ssh -p {PORT} anyone@localhost")
    await asyncio.Event().wait()  # run forever


def main() -> None:
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")


if __name__ == "__main__":
    main()