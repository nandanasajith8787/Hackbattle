import os
from google import genai
from dotenv import load_dotenv

load_dotenv()

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

SYSTEM_PROMPT = """You are acting as an authentic Ubuntu 22.04 LTS Linux server terminal shell.

Strict Rules:
1. Output ONLY the raw console output that executing the user's command would produce.
2. Do NOT write markdown code blocks, explanations, conversational text, or notes.
3. Pretend to execute every command naturally within the mock state context provided.
4. If a command fails or is unknown, generate realistic standard Linux error output in the EXACT format: bash: <command>: command not found

Example of correct 'ls -la' output style (adapt filenames/sizes to the actual context given):
total 16
drwxr-x--- 3 admin admin 4096 Jun 12 09:14 .
drwxr-xr-x 4 root  root  4096 Jun 10 18:02 ..
-rw-r----- 1 admin admin 2048 Jun 11 22:40 backup.sql
-rw-r--r-- 1 admin admin  512 Jun 11 20:15 notes.txt

Always output a FULL, complete listing like this example — one line per file/directory, never truncate.
"""

async def get_shell_response(command: str, fs_state: dict, history: list) -> str:
    cwd = fs_state.get("cwd", "/home/admin")
    files = fs_state.get("files", [])
    contents = fs_state.get("contents", {})

    context = (
        f"Current Directory: {cwd}\n"
        f"Files that exist in this directory (use these EXACT names, nothing else): {files}\n"
        f"File contents (if relevant to the command): {contents}\n"
        f"Recent Commands/Responses: {history[-5:]}"
    )
    user_message = f"Context:\n{context}\n\nCommand: {command}"

    try:
        response = await client.aio.models.generate_content(
            model="gemini-3.6-flash",
            contents=user_message,
            config={
                "system_instruction": SYSTEM_PROMPT,
                "max_output_tokens": 2048,
               
            }
        )

        text = None
        if response.candidates:
            parts = response.candidates[0].content.parts
            if parts:
                text = "".join(p.text for p in parts if getattr(p, "text", None))

        if not text:
            reason = response.candidates[0].finish_reason if response.candidates else None
            print(f"[llm_shell warning] Empty response from Gemini (finish_reason={reason})")
            return f"bash: {command}: command not found"

        return text.strip()
    except Exception as e:
        print(f"[llm_shell error] {e}")
        return f"bash: {command}: command not found"


if __name__ == "__main__":
    import asyncio

    async def _test():
        test_fs = {"cwd": "/home/admin", "files": ["backup.sql", "notes.txt"], "contents": {}}
        test_history = ["whoami", "pwd"]

        print("--- Test 1: cat notes.txt ---")
        print(await get_shell_response("cat notes.txt", test_fs, test_history))

        print("\n--- Test 2: ls -la ---")
        print(await get_shell_response("ls -la", test_fs, test_history))

        print("\n--- Test 3: pwd ---")
        print(await get_shell_response("pwd", test_fs, test_history))

        print("\n--- Test 4: unknown command ---")
        print(await get_shell_response("frobnicate --wizard", test_fs, test_history))

    asyncio.run(_test())