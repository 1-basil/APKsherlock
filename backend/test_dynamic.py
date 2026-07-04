import sys
import json
import os
from analyzer.dynamic.dynamic_engine import DynamicEngine

def main():
    if len(sys.argv) < 3:
        print("Usage: python test_dynamic.py <path_to_apk> <package_name>")
        sys.exit(1)

    apk_path = sys.argv[1]
    package_name = sys.argv[2]
    
    if not os.path.exists(apk_path):
        print(f"Error: APK not found at {apk_path}")
        sys.exit(1)

    print("======================================================================")
    print("  FORENSICDROID DYNAMIC ANALYSIS ENGINE")
    print("======================================================================")
    
    engine = DynamicEngine(apk_path=apk_path, package_name=package_name, duration=30)
    
    if not engine.check_environment():
        print("\n❌ Environment Check Failed")
        print("Please ensure:")
        print("  1. 'adb' is installed and added to your system PATH.")
        print("  2. An Android Emulator is currently running or a device is connected.")
        print("  3. The device has root access (su) and tcpdump installed.")
        sys.exit(1)
        
    print("\n✅ Environment OK. Emulator detected.")
    results = engine.run_analysis()
    
    print("\n======================================================================")
    print("  DYNAMIC ANALYSIS RESULTS")
    print("======================================================================")
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
