# scanners/clamav_scanner.py
import subprocess

def scan_file(file_path):
    result = subprocess.run(['clamscan', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return parse_result(result.stdout)

def parse_result(output):
    if 'FOUND' in output:
        return {'status': 'infected', 'details': output}
    elif 'OK' in output:
        return {'status': 'clean', 'details': output}
    else:
        return {'status': 'error', 'details': output}