"""
Person 1 — Honeypot Core

Accepts any SSH login, buffers attacker keystrokes until Enter, then:
  1. calls Person 2's get_shell_response()   -> realistic fake output
  2. calls Person 3's fs.apply()             -> updates fake filesystem state
  3. calls Person 4's db.log_command()       -> persists the interaction
  4. checks the bait file + re-scores the session's fingerprint

This file only depends on the AGREED signatures:
    get_shell_response(command: str, fs_state: dict, history: list) -> str   (async)
    fs.apply(command: str) -> None
    fs.snapshot() -> dict
    fs.check_bait_accessed(command: str) -> bool
    db.log_command(session_id: str, command: str, response: str) -> None     (async)
    db.flag_session_malicious(session_id: str, reason: str) -> None         (async)
    db.update_fingerprint(session_id: str, score: float, label: str) -> None (async)

Swap the stub imports for the real modules once Person 2/3/4 land theirs —
nothing else in this file should need to change.
"""

import time

import asyncssh

from server.handler.llm_shell import get_shell_response
from server.state import FakeFS
from server.fingerprint import score_session
from server import db


class HoneypotSSHServer(asyncssh.SSHServer):
    """Auth handler — accepts literally any username/password."""

    def connection_made(self, conn):
        peer = conn.get_extra_info("peername")
        self.client_ip = peer[0] if peer else "unknown"
        print(f"[+] Connection from {self.client_ip}")

    def connection_lost(self, exc):
        print(f"[-] Connection closed ({self.client_ip})"
              + (f": {exc}" if exc else ""))

    def begin_auth(self, username):
        # Returning True means "auth is required" -> validate_password gets called.
        # (If we returned False here asyncssh would let the client in with NO
        # auth step at all, which looks suspicious to real attacker tooling —
        # we want the normal password prompt, we just always accept it.)
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        self.username = username
        return True  # accept anything

    def public_key_auth_supported(self):
        return False


async def handle_client(process: asyncssh.SSHServerProcess) -> None:
    """One call of this = one interactive attacker session."""

    username = process.get_extra_info("username") or "root"
    peer = process.get_extra_info("peername")
    client_ip = peer[0] if peer else "unknown"

    fs = FakeFS()
    history: list[dict] = []
    # FIX: fingerprint.score_session() needs per-command timestamps, but
    # nothing was tracking them at the session level before — only `history`
    # (commands/responses, no times) existed. Track them alongside history.
    command_timestamps: list[float] = []

    # Whether we've already flagged this session, so we don't spam
    # flag_session_malicious() on every subsequent command once triggered.
    already_flagged = False

    # Person 4's create_session() only takes ip and generates+returns the
    # session_id itself (it doesn't take username, and there's no separate
    # close_session() — the sessions table has no "ended" concept yet).
    session_id = await db.create_session(ip=client_ip)
    print(f"[session {session_id[:8]}] {username}@{client_ip} connected")

    def prompt() -> str:
        cwd = fs.snapshot().get("cwd", "~")
        return f"{username}@prod-web01:{cwd}$ "

    process.stdout.write(f"Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n")
    process.stdout.write(prompt())

    buffer = ""
    try:
        async for data in process.stdin:
            for ch in data:
                # --- Enter: full command entered ---
                if ch in ("\r", "\n"):
                    command = buffer.strip()
                    buffer = ""
                    process.stdout.write("\r\n")

                    if not command:
                        process.stdout.write(prompt())
                        continue

                    if command in ("exit", "logout"):
                        process.stdout.write("logout\r\n")
                        process.exit(0)
                        return

                    fs_state = fs.snapshot()
                    command_timestamps.append(time.monotonic())

                    # 1. Person 2: get realistic fake output
                    try:
                        response = await get_shell_response(
                            command=command,
                            fs_state=fs_state,
                            history=history,
                        )
                    except Exception as e:
                        # Fail closed — never leak a stack trace to the attacker,
                        # never crash the session over an LLM hiccup.
                        print(f"[session {session_id[:8]}] get_shell_response error: {e}")
                        response = ""

                    # 2. Person 3: update fake filesystem state
                    try:
                        fs.apply(command)
                    except Exception as e:
                        print(f"[session {session_id[:8]}] fs.apply error: {e}")

                    # 3. Person 4: log it
                    # FIX: this was called without `await`, which for an async
                    # def just creates a coroutine and never runs it — nothing
                    # was actually being written to the commands table.
                    try:
                        await db.log_command(
                            session_id=session_id,
                            command=command,
                            response=response,
                        )
                    except Exception as e:
                        print(f"[session {session_id[:8]}] log_command error: {e}")

                    history.append({"command": command, "response": response})

                    # 4. Bait / fingerprint checks — previously written but
                    # never called from anywhere.
                    try:
                        if not already_flagged and fs.check_bait_accessed(command):
                            await db.flag_session_malicious(
                                session_id, reason="credentials.txt accessed"
                            )
                            already_flagged = True
                            print(f"[session {session_id[:8]}] FLAGGED: bait file accessed")
                    except Exception as e:
                        print(f"[session {session_id[:8]}] flag_session_malicious error: {e}")

                    try:
                        all_commands = [h["command"] for h in history]
                        if len(all_commands) > 3:
                            result = score_session(all_commands, command_timestamps)
                            await db.update_fingerprint(
                                session_id,
                                score=result["risk_score"],
                                label=result["session_type"],
                            )
                    except Exception as e:
                        print(f"[session {session_id[:8]}] score_session error: {e}")

                    if response:
                        process.stdout.write(response.rstrip("\n").replace("\n", "\r\n") + "\r\n")

                    process.stdout.write(prompt())

                # --- Backspace ---
                elif ch in ("\x7f", "\b"):
                    if buffer:
                        buffer = buffer[:-1]
                        process.stdout.write("\b \b")

                # --- Ctrl+C ---
                elif ch == "\x03":
                    buffer = ""
                    process.stdout.write("^C\r\n" + prompt())

                # --- Ordinary printable character ---
                else:
                    buffer += ch
                    process.stdout.write(ch)

    except asyncssh.BreakReceived:
        pass
    finally:
        # NOTE: Person 4's db.py has no close_session() yet — the sessions
        # table doesn't track an "ended" state. Flag this to Person 4 if you
        # want session end-times recorded; harmless to skip for the demo.
        try:
            process.exit(0)
        except Exception:
            pass