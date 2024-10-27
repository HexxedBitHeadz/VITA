from flask import Flask, request, jsonify
import subprocess
import os

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/scan', methods=['POST'])
def scan_file():
 if 'file' not in request.files:
	 return jsonify({'error': 'No file part'}), 400
 file = request.files['file']
 filepath = os.path.join(UPLOAD_FOLDER, file.filename)
 file.save(filepath)

 # Run ExifTool scan
 result = subprocess.run(['exiftool', filepath], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
 return jsonify({'output': result.stdout})

if __name__ == '__main__':
 app.run(host='0.0.0.0', port=5003)