import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SYSTEM_PROMPT = """You are acting as an authentic Ubuntu 22.04 LTS Linux server terminal shell.
Strict Rules:
1. Output ONLY the raw console output that executing the user's command would produce.
2. Do NOT write markdown code blocks, explanations, conversational text, or notes.
3. Pretend to execute every command naturally within the mock state context provided.
4. If a command fails or is unknown, generate realistic standard Linux error output.
"""

def get_shell_response(command: str, fs_state: dict, history: list) -> str:
    cwd = fs_state.get("cwd", "/home/admin")
    files = fs_state.get("files", [])
    
    context = f"Current Directory: {cwd}\nDirectory Contents: {files}\nRecent Commands: {history[-5:]}"
    user_message = f"Context:\n{context}\n\nCommand: {command}"
    
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message}
            ],
            temperature=0.2,
            max_tokens=300
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"bash: {command}: command not found"

if __name__ == "__main__":
    test_fs = {"cwd": "/home/admin", "files": ["backup.sql", "notes.txt"]}
    test_history = ["whoami", "pwd"]
    print("--- Testing LLM Shell Response ---")
    print(get_shell_response("cat notes.txt", test_fs, test_history))