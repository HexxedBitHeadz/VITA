from flask import Flask, request, redirect, url_for, render_template, jsonify
import os, requests, logging, pefile, json, hashlib
from werkzeug.utils import secure_filename
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from concurrent.futures import ThreadPoolExecutor, as_completed

UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = set(['exe', 'dll', 'docx', 'doc', 'xlsx', 'pptx'])

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Database setup
engine = create_engine('sqlite:///./database.db')

Base = declarative_base()

class ScanResult(Base):
    __tablename__ = 'scan_results'
    id = Column(Integer, primary_key=True)
    filename = Column(String(256))
    file_hash = Column(String(64))
    upload_time = Column(DateTime, default=datetime.utcnow)
    clamav_result = Column(Text)
    yara_result = Column(Text)
    exiftool_result = Column(Text)
    pefile_result = Column(Text)


Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

# Helper function to check allowed file types
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Function to dispatch file to Clamav (Kenny) for scanning
def scan_with_clamav(filepath):
    try:
        with open(filepath, 'rb') as f:
            files = {'file': f}
            logger.info(f"Sending {filepath} to Kenny for ClamAV scanning")
            response = requests.post('http://kenny:5001/scan', files=files)
            response.raise_for_status()
            return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error scanning with ClamAV: {e}")
        return {'error': str(e)}

# Function to dispatch file to YARA (Kyle) for scanning
def scan_with_yara(filepath):
    try:
        with open(filepath, 'rb') as f:
            files = {'file': f}
            logger.info(f"Sending {filepath} to Kyle for yara scanning")
            response = requests.post('http://kyle:5002/scan', files=files)
            response.raise_for_status()
            return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error scanning with Yara: {e}")
        return {'error': 'Failed to scan with Yara. Please try again later.'}

# Function to dispatch file to ExifTool (Stan) for metadata extraction
def scan_with_exiftool(filepath):
    try:
        with open(filepath, 'rb') as f:
            files = {'file': f}
            logger.info(f"Sending {filepath} to Stan for exiftool scanning")
            response = requests.post('http://stan:5003/scan', files=files)
            response.raise_for_status()
            return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error scanning with exiftool: {e}")
        return {'error': str(e)}

# Function to analyze file with pefile (Cartman)
def analyze_with_pefile(filepath):
    try:
        pe = pefile.PE(filepath)
        api_calls = []
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    api_calls.append({
                        'library': entry.dll.decode('utf-8'),
                        'function': imp.name.decode('utf-8') if imp.name else f'Ordinal: {imp.ordinal}'
                    })
        return api_calls
    except pefile.PEFormatError as e:
        logger.error(f"Error parsing PE file: {e}")
        return {'error': str(e)}
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return {'error': str(e)}

def generate_file_hash(filepath, hash_type='sha256'):
    hash_func = getattr(hashlib, hash_type)()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            hash_func.update(chunk)
    return hash_func.hexdigest()

# Route for uploading files
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            logger.error('No file part in the request.')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            logger.error('No file selected for upload.')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            try:
                # Save the file
                file.save(filepath)

                # Generate the file hash immediately after saving
                file_hash = generate_file_hash(filepath)
                file_size = os.path.getsize(filepath)

                logger.info(
                    f'File {filename} ({file_size / 1024:.2f} KB) '
                    f'uploaded successfully with hash {file_hash}.'
                )
            except Exception as e:
                logger.error(f'Error saving or hashing file {filename}: {e}')
                return 'An error occurred during file upload', 500

            # Check if the file with the same hash already exists
            existing_result = session.query(ScanResult).filter_by(file_hash=file_hash).first()
            if existing_result:
                logger.info(f"File with hash {file_hash} already scanned. Redirecting to result page.")
                return redirect(url_for('show_result', result_id=existing_result.id))

            # Define scan functions for concurrent execution
            scan_functions = {
                'clamav': lambda: scan_with_clamav(filepath),
                'yara': lambda: scan_with_yara(filepath),
                'exiftool': lambda: scan_with_exiftool(filepath)
            }

            results = {}

            # Run scans concurrently using ThreadPoolExecutor
            with ThreadPoolExecutor() as executor:
                futures = {executor.submit(fn): name for name, fn in scan_functions.items()}
                for future in as_completed(futures):
                    scan_name = futures[future]
                    try:
                        results[scan_name] = future.result()
                        logger.info(f'{scan_name} scan completed.')
                    except Exception as e:
                        results[scan_name] = {'error': str(e)}
                        logger.error(f'Error in {scan_name} scan: {e}')

            # Perform PE analysis if it's an executable
            pefile_res = analyze_with_pefile(filepath) if filename.lower().endswith('.exe') else {}

            # Assemble the scan result
            scan_result = ScanResult(
                filename=filename,
                file_hash=file_hash,
                clamav_result=json.dumps(results.get('clamav', {})),
                yara_result=json.dumps(results.get('yara', {})),
                exiftool_result=json.dumps(results.get('exiftool', {})),
                pefile_result=json.dumps(pefile_res)
            )

            # Commit the scan result to the database
            try:
                session.add(scan_result)
                session.commit()
                logger.info(f'Scan result for {filename} saved successfully.')
            except Exception as e:
                session.rollback()  # Rollback if commit fails
                logger.error(f'Database commit failed: {e}')
                return 'An error occurred while saving the scan result', 500

            # Redirect to the result page
            return redirect(url_for('show_result', result_id=scan_result.id))

    return render_template('upload.html')

def send_update(message):
    print(message)


@app.route('/result/<int:result_id>')
def show_result(result_id):
    result = session.query(ScanResult).filter_by(id=result_id).first()

    if result:
        try:
            yara_result = json.loads(result.yara_result) if result.yara_result else None
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding YARA result JSON: {e}")
            yara_result = None

        try:
            pefile_result = json.loads(result.pefile_result) if result.pefile_result else None
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding PE file result JSON: {e}")
            pefile_result = None

        return render_template(
            'result.html', 
            filename=result.filename,
            file_hash=result.file_hash,
            clamav_result=result.clamav_result,
            yara_result=yara_result,
            exiftool_result=result.exiftool_result,
            pefile_result=pefile_result
        )
    else:
        return 'Result not found', 404

@app.route('/api/scan', methods=['POST'])
def api_scan():
    logger.info('Received API scan request.')

    file_hash = generate_file_hash(filepath)
    logger.info(f'API scan request for {filename} with hash {file_hash}.')


    if 'file' not in request.files:
        logger.error('No file part in the request.')
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        logger.error('No file selected for upload.')
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Perform the scans
        clamav_res = scan_with_clamav(filepath)
        yara_res = scan_with_yara(filepath)
        exiftool_res = scan_with_exiftool(filepath)
        pefile_res = analyze_with_pefile(filepath) if filename.lower().endswith('.exe') else {}

        result = {
            'filename': filename,
            'file_hash': file_hash,
            'clamav': clamav_res,
            'yara': yara_res,
            'exiftool': exiftool_res,
            'pefile': pefile_res
        }
        logger.info(f'Successfully scanned {filename} via API.')
        return jsonify(result), 200

    logger.error(f'Invalid file type: {file.filename}')
    return jsonify({'error': f'File type {file.filename.rsplit(".", 1)[1]} not allowed'}), 400

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(host='0.0.0.0', port=5000)