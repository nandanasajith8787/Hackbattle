import aiosqlite
import uuid
from datetime import datetime, timezone

DB_PATH = "../honeypot.db"


async def init_db():
    """Create tables if they don't exist yet. Call this once at server startup."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                ip TEXT,
                started_at TEXT,
                status TEXT DEFAULT 'normal',
                flag_reason TEXT,
                fingerprint_score REAL,
                fingerprint_label TEXT
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                command TEXT,
                response TEXT,
                timestamp TEXT
            )
        """)
        await db.commit()


async def create_session(ip: str) -> str:
    """Call this the moment an attacker connects. Returns the new session_id."""
    session_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO sessions (id, ip, started_at) VALUES (?, ?, ?)",
            (session_id, ip, started_at)
        )
        await db.commit()
    return session_id


async def log_command(session_id: str, command: str, response: str):
    """Call this after every command the attacker types."""
    timestamp = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO commands (session_id, command, response, timestamp) VALUES (?, ?, ?, ?)",
            (session_id, command, response, timestamp)
        )
        await db.commit()


async def flag_session_malicious(session_id: str, reason: str = "honeytoken accessed"):
    """Mark a session as high-confidence malicious (your Person 3 bridge function)."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE sessions SET status = ?, flag_reason = ? WHERE id = ?",
            ("HIGH_CONFIDENCE_MALICIOUS", reason, session_id)
        )
        await db.commit()


async def update_fingerprint(session_id: str, score: float, label: str):
    """Called by Person 2's fingerprinting logic to update a session's classification."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE sessions SET fingerprint_score = ?, fingerprint_label = ? WHERE id = ?",
            (score, label, session_id)
        )
        await db.commit()


async def get_all_sessions():
    """Used by the FastAPI /sessions endpoint."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM sessions ORDER BY started_at DESC")
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def get_session_commands(session_id: str):
    """Used by the FastAPI /sessions/{id}/commands endpoint."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM commands WHERE session_id = ? ORDER BY timestamp ASC",
            (session_id,)
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]