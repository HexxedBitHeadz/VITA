import os
import yara
from flask import Flask, request, jsonify

app = Flask(__name__)

# Path to the consolidated YARA rules file
YARA_RULES_FILE = '/home/kyle/Desktop/yara_scanner/yara-rules-full.yar'
UPLOAD_FOLDER = 'uploads'

# Ensure the upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    # Compile and load the YARA rules from the consolidated file
    try:
        rules = yara.compile(filepath=YARA_RULES_FILE)
    except yara.Error as e:
        return jsonify({'error': f'Failed to compile YARA rules: {str(e)}'}), 500

    # Match the uploaded file against the compiled rules
    try:
        matches = rules.match(filepath)
    except yara.Error as e:
        return jsonify({'error': f'Failed to match file: {str(e)}'}), 500

    # Return the matches
    return jsonify({'matches': [match.rule for match in matches]})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002)