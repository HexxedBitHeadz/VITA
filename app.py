from flask import Flask, render_template, request
from oletools.olevba import VBA_Parser
from oletools.oleid import OleID
import yara, subprocess, os, re, oletools.mraptor, json

app = Flask(__name__)
UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
RULES_FOLDER = '/app/yara-rules/packages/full/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def load_yara_rules():
    rule_files = {}
    for root, _, files in os.walk(RULES_FOLDER):
        for file in files:
            if file.endswith('.yar') or file.endswith('.yara'):
                rule_path = os.path.join(root, file)
                rule_files[file] = rule_path
    return yara.compile(filepaths=rule_files) if rule_files else None

try:
    yara_rules = load_yara_rules()
except yara.SyntaxError as e:
    print(f"Error loading YARA rules: {e}")
    yara_rules = None

def extract_windows_api_calls(vba_macros):
    api_calls = set()
    api_pattern = re.compile(r'\b(CreateFile|ReadFile|WriteFile|CloseHandle|VirtualAlloc|VirtualFree|GetProcAddress|LoadLibrary|WinExec|ShellExecute|RegOpenKey|RegSetValue|RegQueryValue|InternetOpen|InternetConnect|HttpOpenRequest|HttpSendRequest|WSASocket|connect|send|recv)\b', re.IGNORECASE)
    for macro in vba_macros:
        code = macro["vba_code_snippet"]
        matches = api_pattern.findall(code)
        api_calls.update(matches)
    return sorted(api_calls)

def analyze_office_file(filepath):
    results = {}
    oid = OleID(filepath)
    indicators = oid.check()
    results['oleid'] = {str(i.id): str(i.value.decode(errors="ignore") if isinstance(i.value, bytes) else i.value) for i in indicators}
    
    results['vba_macros'] = []
    results['macro_dangerous'] = "False"
    results["windows_api_calls"] = []

    vba_parser = VBA_Parser(filepath)
    if vba_parser.detect_vba_macros():
        all_vba_code = ""
        for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
            vba_code_str = vba_code.decode(errors="ignore") if isinstance(vba_code, bytes) else str(vba_code)
            all_vba_code += vba_code_str + "\n"
            results['vba_macros'].append({
                'filename': filename,
                'stream_path': stream_path,
                'vba_filename': vba_filename,
                'vba_code_snippet': vba_code_str
            })
        raptor = oletools.mraptor.MacroRaptor(all_vba_code)
        results['macro_dangerous'] = str(raptor.scan())
        results["windows_api_calls"] = extract_windows_api_calls(results["vba_macros"])
    vba_parser.close()
    return results


def run_capa(filepath):
    capa_command = f"capa --json {filepath}"
    capa_output = subprocess.getoutput(capa_command)
    try:
        data = json.loads(capa_output)
        data.pop("analysis", None)
        return data
    except json.JSONDecodeError:
        return None

@app.route("/")
def upload():
    return render_template("upload.html")

@app.route("/", methods=["POST"])
def handle_upload():
    file = request.files.get("file")
    if not file or file.filename == "":
        return "No file selected", 400

    filename = file.filename
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    try:
        file.save(filepath)
    except Exception as e:
        return f"Error saving file: {e}", 500

    clamav_result = subprocess.getoutput(f"clamscan {filepath}")
    yara_result = []
    if yara_rules:
        matches = yara_rules.match(filepath)
        yara_result = [str(match) for match in matches] if matches else ["No matches found."]
    else:
        yara_result = ["No rules loaded."]

    capa_result = run_capa(filepath)

    oletools_result = analyze_office_file(filepath) if filename.lower().endswith((".doc", ".docx", ".xls", ".xlsm", ".pptm", ".docm")) else None

    return render_template(
        "results.html",
        clamav_result=clamav_result,
        yara_result=yara_result,
        capa_result=capa_result,
        oletools_result=oletools_result,
        filename=filename
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
