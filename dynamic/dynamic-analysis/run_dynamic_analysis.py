"""
End-to-end pipeline: static extraction -> emulator dynamic capture ->
correlation. Run this directly, or import run_pipeline() from your
Flask API.

Usage:
    python run_dynamic_analysis.py path/to/sample.apk
"""

import sys
import os
import json
import time

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from apk_extractor import analyze_apk  # your existing static module

from emulator_controller import (
    start_emulator, install_apk, launch_app,
    simulate_interaction, stop_emulator, get_package_name,
)
from pcap_parser import parse_pcap
from correlate import correlate

AVD_NAME = "dynamic-analysis"
CAPTURE_SECONDS = 45
PCAP_PATH = "capture.pcap"


def run_pipeline(apk_path):
    print("=== STATIC ANALYSIS ===")
    static_result = analyze_apk(apk_path)
    print(json.dumps(static_result, indent=2)[:500], "...")

    print("\n=== DYNAMIC ANALYSIS ===")
    package_name = static_result["package_name"]
    emu_proc = start_emulator(AVD_NAME, PCAP_PATH)

    try:
        install_apk(apk_path)
        launch_app(package_name)
        simulate_interaction(taps=5, delay=2)

        print(f"[*] Letting app run for {CAPTURE_SECONDS}s to capture traffic...")
        time.sleep(CAPTURE_SECONDS)
    finally:
        stop_emulator(emu_proc)
        time.sleep(3)  # let the pcap file flush to disk

    print("[*] Parsing captured traffic...")
    dynamic_result = parse_pcap(PCAP_PATH)

    print("\n=== CORRELATION ===")
    correlation_result = correlate(static_result["iocs"], dynamic_result)

    return {
        "static": static_result,
        "dynamic": dynamic_result,
        "correlation": correlation_result,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python run_dynamic_analysis.py <path_to_apk>")
        sys.exit(1)

    result = run_pipeline(sys.argv[1])
    with open("analysis_result.json", "w") as f:
        json.dump(result, f, indent=2)

    print("\n[*] Done. Full results written to analysis_result.json")