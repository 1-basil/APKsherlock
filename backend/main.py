from fastapi import FastAPI, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import os
import json

from config import settings

app = FastAPI(title="ForensicDroid API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "Welcome to ForensicDroid API"}

import uuid
import asyncio
from concurrent.futures import ThreadPoolExecutor

# Persistent store for task results to survive server restarts/reloads
# Maps task_id -> {"status": "pending" | "running" | "completed" | "failed", "result": dict, "error": str}
DB_FILE = os.path.join(settings.REPORTS_DIR, "tasks_db.json")

def load_db() -> dict:
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, "r") as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_db(db: dict):
    try:
        os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
        with open(DB_FILE, "w") as f:
            json.dump(db, f, indent=2)
    except:
        pass

executor = ThreadPoolExecutor(max_workers=4)

def run_analysis_sync(apk_path: str, task_id: str):
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from test_analyzer import run_full_analysis
    try:
        results = run_full_analysis(apk_path)
        db = load_db()
        db[task_id] = {"status": "completed", "result": results}
        save_db(db)
    except Exception as e:
        db = load_db()
        db[task_id] = {"status": "failed", "error": str(e)}
        save_db(db)

@app.post("/upload")
async def upload_apk(file: UploadFile = File(...)):
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    file_path = os.path.join(settings.UPLOAD_DIR, file.filename)
    
    with open(file_path, "wb") as buffer:
        content = await file.read()
        buffer.write(content)
        
    task_id = str(uuid.uuid4())
    db = load_db()
    db[task_id] = {"status": "running"}
    save_db(db)
    
    # Run the blocking analysis in a threadpool so we don't block the FastAPI event loop
    asyncio.get_running_loop().run_in_executor(executor, run_analysis_sync, file_path, task_id)
        
    return {"task_id": task_id, "status": "running", "filename": file.filename}

@app.get("/status/{task_id}")
async def get_status(task_id: str):
    db = load_db()
    if task_id not in db:
        return {"error": "Task not found", "status": "failed"}
    return db[task_id]
