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

def get_shell_response(command: str, fs_state: dict, history: list) -> str:
    cwd = fs_state.get("cwd", "/home/admin")
    files = fs_state.get("files", [])

    context = (
        f"Current Directory: {cwd}\n"
        f"Files that exist in this directory (use these EXACT names, nothing else): {files}\n"
        f"Recent Commands: {history[-5:]}"
    )
    user_message = f"Context:\n{context}\n\nCommand: {command}"

    try:
        response = client.models.generate_content(
            model="gemini-3.6-flash",
            contents=user_message,
            config={
                "system_instruction": SYSTEM_PROMPT,
                "max_output_tokens": 1024,
            }
        )
        return response.text.strip()
    except Exception as e:
        print(f"[llm_shell error] {e}")
        return f"bash: {command}: command not found"

if __name__ == "__main__":
    test_fs = {"cwd": "/home/admin", "files": ["backup.sql", "notes.txt"]}
    test_history = ["whoami", "pwd"]

    print("--- Test 1: cat notes.txt ---")
    print(get_shell_response("cat notes.txt", test_fs, test_history))

    print("\n--- Test 2: ls -la ---")
    print(get_shell_response("ls -la", test_fs, test_history))

    print("\n--- Test 3: pwd ---")
    print(get_shell_response("pwd", test_fs, test_history))

    print("\n--- Test 4: unknown command ---")
    print(get_shell_response("frobnicate --wizard", test_fs, test_history))