# test_db.py
import asyncio
from db import init_db, create_session, log_command, flag_session_malicious, update_fingerprint, get_all_sessions, get_session_commands

async def main():
    await init_db()

    session_id = await create_session("192.168.1.100")
    print("Created session:", session_id)

    await log_command(session_id, "whoami", "deploy")
    await log_command(session_id, "cat credentials.txt", "db_user=admin\ndb_pass=Winter2024!")

    await flag_session_malicious(session_id, "accessed credentials.txt")
    await update_fingerprint(session_id, 0.85, "possible LLM agent")

    sessions = await get_all_sessions()
    print("\nAll sessions:", sessions)

    commands = await get_session_commands(session_id)
    print("\nCommands for this session:", commands)

asyncio.run(main())
