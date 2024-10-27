# scanners/exiftool_scanner.py
import subprocess
import json

def scan_file(file_path):
    result = subprocess.run(['exiftool', '-j', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.stdout:
        metadata = json.loads(result.stdout)[0]
        return {'status': 'success', 'details': metadata}
    else:
        return {'status': 'error', 'details': result.stderr}