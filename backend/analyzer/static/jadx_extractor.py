import os
import subprocess
import shutil
from pathlib import Path

class JadxExtractor:
    def __init__(self, apk_path: str, output_dir: str):
        self.apk_path = apk_path
        self.output_dir = output_dir
        self.max_files = 3000
        self.max_file_size = 1024 * 1024 * 2 # 2MB max per file
        
    def decompile(self) -> dict:
        """
        Runs JADX to decompile the APK, then reads .java files.
        Returns a dict of {filepath: content}
        """
        jadx_out = os.path.join(self.output_dir, "jadx_source")
        
        
        # Check for local JADX installation first
        local_jadx = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "jadx", "bin", "jadx.bat")
        user_jadx = r"C:\jadx-1.5.5\bin\jadx.bat"
        
        if os.path.exists(local_jadx):
            jadx_cmd = local_jadx
        elif os.path.exists(user_jadx):
            jadx_cmd = user_jadx
        else:
            jadx_cmd = "jadx"
        
        # Run JADX
        # -d output_dir
        # -q quiet
        # -r do not decode resources (we only want Java code to save time and space)
        cmd = [jadx_cmd, "-d", jadx_out, "-q", "-r", self.apk_path]
        
        try:
            print(f"    [*] Running JADX (this may take a few minutes)...")
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            raise Exception("JADX is not installed or not in system PATH. Please install JADX.")
        except subprocess.CalledProcessError as e:
            raise Exception(f"JADX decompilation failed: {e}")
            
        return self._load_java_files(jadx_out)
        
    def _load_java_files(self, source_dir: str) -> dict:
        java_files = {}
        file_count = 0
        
        sources_path = os.path.join(source_dir, "sources")
        if not os.path.exists(sources_path):
            sources_path = source_dir # fallback if jadx structure varies
            
        for root, dirs, files in os.walk(sources_path):
            for file in files:
                if file.endswith(".java"):
                    if file_count >= self.max_files:
                        break
                        
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, sources_path)
                    # Normalize backslashes to forward slashes for internal consistency
                    rel_path = rel_path.replace("\\", "/")
                    
                    try:
                        # Skip massive files to prevent memory explosion
                        if os.path.getsize(file_path) > self.max_file_size:
                            continue
                            
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            if content.strip():
                                java_files[rel_path] = content
                                file_count += 1
                    except Exception:
                        pass
                        
            if file_count >= self.max_files:
                break
                
        return java_files
