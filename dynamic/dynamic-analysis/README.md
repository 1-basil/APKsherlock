# Dynamic Analysis — One-Time Setup

This only needs to be done once on your machine before the demo.

## 1. Install Android SDK command-line tools
If you already have Android Studio, you have this — just make sure these
are on your PATH:
- `<sdk>/emulator/emulator`
- `<sdk>/platform-tools/adb`

## 2. Install tshark (for pcap parsing)
- macOS: `brew install wireshark` (installs tshark CLI too)
- Ubuntu/Debian: `sudo apt install tshark`
- Windows: install Wireshark, tick "Install TShark" during setup

## 3. Create the AVD (Android Virtual Device)
Easiest via Android Studio GUI: Tools → Device Manager → Create Device.
Name it exactly `dynamic-analysis` (or change AVD_NAME in
run_dynamic_analysis.py to match).

Pick an x86_64 system image **without Google Play** (the plain "Google
APIs" image) — Play Store images are slower to boot and you don't need
them for this.

Command-line alternative:
```bash
sdkmanager "system-images;android-30;google_apis;x86_64"
avdmanager create avd -n dynamic-analysis -k "system-images;android-30;google_apis;x86_64"
```

## 4. Install Python dependencies
```bash
pip install -r requirements.txt
```

## 5. Test it
```bash
python run_dynamic_analysis.py /path/to/some_test.apk
```
The first boot will be slow (30-60s) — subsequent runs are faster once
the AVD has a cached snapshot state, though this script disables
snapshots (`-no-snapshot`) to guarantee a clean state per sample, which
is what you want for reproducible forensic analysis anyway.

## Demo-day tip
Pre-boot the emulator once before your presentation slot so the audience
doesn't watch a cold boot. Run one throwaway sample through the pipeline
beforehand to warm everything up.