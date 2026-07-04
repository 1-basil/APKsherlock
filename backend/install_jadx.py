import os
import urllib.request
import zipfile
import io

print("Downloading JADX...")
url = "https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip"
resp = urllib.request.urlopen(url)
print("Extracting...")
z = zipfile.ZipFile(io.BytesIO(resp.read()))
z.extractall("jadx")
print("Done! JADX is now installed in the jadx/ directory.")
