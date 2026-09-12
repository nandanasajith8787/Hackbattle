from fastapi import FastAPI, WebSocket, WebSocketDisconnect  # pyright: ignore[reportMissingImports]
from fastapi.middleware.cors import CORSMiddleware  # pyright: ignore[reportMissingImports]
import sys, os, asyncio

# Import db.py through the server package so static analysis can resolve it.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from server.db import get_all_sessions, get_session_commands

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/sessions")
async def sessions():
    """Returns all attacker sessions, newest first."""
    return await get_all_sessions()

@app.get("/sessions/{session_id}/commands")
async def session_commands(session_id: str):
    """Returns the full command transcript for one session."""
    return await get_session_commands(session_id)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Pushes updated session list every 2 seconds — simplest live-update approach."""
    await websocket.accept()
    try:
        while True:
            data = await get_all_sessions()
            await websocket.send_json(data)
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass