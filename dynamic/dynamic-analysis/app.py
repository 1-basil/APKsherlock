"""
Self-hosted analysis server for the hackathon demo.

Since only one emulator instance can run at a time, incoming APK uploads
are queued and processed one at a time by a single background worker
thread. The frontend uploads a file, gets a job_id back immediately,
then polls /api/status/<job_id> until the result is ready.

Run with:  python app_server.py
Then it's reachable at http://<your-ip>:5000 from other devices on
your local network, or via ngrok for external access during the demo.
"""

import os
import sys
import uuid
import queue
import threading
import tempfile
import traceback

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, request, jsonify
from flask_cors import CORS

from apk_extractor import analyze_apk
from emulator_controller import (
    start_emulator, install_apk, launch_app,
    simulate_interaction, stop_emulator,
)
from pcap_parser import parse_pcap
from correlate import correlate

app = Flask(__name__)
CORS(app)

AVD_NAME = "dynamic-analysis-clean"
CAPTURE_SECONDS = 45

job_queue = queue.Queue()
jobs = {}  # job_id -> {"status": ..., "result": ..., "error": ...}


def worker_loop():
    """Runs forever in the background, processing one APK at a time."""
    while True:
        job_id, apk_path = job_queue.get()
        jobs[job_id]["status"] = "running"

        try:
            static_result = analyze_apk(apk_path)
            package_name = static_result["package_name"]

            pcap_path = f"capture_{job_id}.pcap"
            emu_proc = start_emulator(AVD_NAME, pcap_path)

            try:
                install_apk(apk_path)
                launch_app(package_name)
                simulate_interaction(taps=5, delay=2)
                import time
                time.sleep(CAPTURE_SECONDS)
            finally:
                stop_emulator(emu_proc)
                import time
                time.sleep(3)

            dynamic_result = parse_pcap(pcap_path)
            correlation_result = correlate(static_result["iocs"], dynamic_result)

            jobs[job_id]["status"] = "done"
            jobs[job_id]["result"] = {
                "static": static_result,
                "dynamic": dynamic_result,
                "correlation": correlation_result,
            }

            os.remove(pcap_path)

        except Exception as e:
            jobs[job_id]["status"] = "error"
            jobs[job_id]["error"] = f"{e}\n{traceback.format_exc()}"

        finally:
            if os.path.exists(apk_path):
                os.remove(apk_path)
            job_queue.task_done()


@app.route("/api/analyze", methods=["POST"])
def analyze():
    file = request.files.get("apk")
    if not file:
        return jsonify({"error": "No APK uploaded"}), 400

    job_id = str(uuid.uuid4())
    tmp_path = os.path.join(tempfile.gettempdir(), f"{job_id}.apk")
    file.save(tmp_path)

    jobs[job_id] = {"status": "queued", "result": None, "error": None}
    job_queue.put((job_id, tmp_path))

    queue_position = job_queue.qsize()
    return jsonify({"job_id": job_id, "queue_position": queue_position})


@app.route("/api/status/<job_id>", methods=["GET"])
def status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Unknown job_id"}), 404
    return jsonify(job)


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "queue_size": job_queue.qsize()})


if __name__ == "__main__":
    threading.Thread(target=worker_loop, daemon=True).start()
    print("[*] Server starting on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000)