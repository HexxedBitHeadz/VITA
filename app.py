# Updated app.py with suggested fixes

from flask import Flask, render_template, request, redirect, url_for
from oletools.olevba import VBA_Parser
from oletools.oleid import OleID
import networkx as nx, matplotlib.pyplot as plt, yara, subprocess, os, shutil, threading, re, base64, time, uuid, oletools.mraptor

app = Flask(__name__)
UPLOAD_FOLDER = '/app/uploads'
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
    print(f"Loaded {len(rule_files)} YARA rules: {list(rule_files.keys())}")
    return yara.compile(filepaths=rule_files) if rule_files else None

try:
    yara_rules = load_yara_rules()
except yara.SyntaxError as e:
    print(f"Error loading YARA rules: {e}")
    yara_rules = None

def reload_yara_rules():
    global yara_rules
    time.sleep(600)
    while True:
        try:
            yara_rules = load_yara_rules()
            print("YARA rules updated successfully!")
        except yara.SyntaxError as e:
            print(f"Error updating YARA rules: {e}")
        time.sleep(600)

threading.Thread(target=reload_yara_rules, daemon=True).start()

def extract_payloads(macros):
    payloads = []
    base64_pattern = r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
    for macro in macros:
        code = macro["vba_code_snippet"]
        base64_matches = re.findall(base64_pattern, code)
        for match in base64_matches:
            try:
                decoded = base64.b64decode(match).decode(errors="ignore")
                payloads.append(decoded)
            except:
                continue
    return payloads

def analyze_office_file(filepath):
    results = {}
    oid = OleID(filepath)
    indicators = oid.check()
    results['oleid'] = {str(i.id): str(i.value.decode(errors="ignore") if isinstance(i.value, bytes) else i.value) for i in indicators}
    vba_parser = VBA_Parser(filepath)
    if vba_parser.detect_vba_macros():
        results['vba_macros'] = []
        all_vba_code = ""
        for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
            vba_code_str = vba_code.decode(errors="ignore") if isinstance(vba_code, bytes) else str(vba_code)
            all_vba_code += vba_code_str + "\n"
            results['vba_macros'].append({'filename': filename, 'stream_path': stream_path, 'vba_filename': vba_filename, 'vba_code_snippet': vba_code_str})
        raptor = oletools.mraptor.MacroRaptor(all_vba_code)
        results['macro_dangerous'] = str(raptor.scan())
        results["extracted_payloads"] = extract_payloads(results["vba_macros"])
    vba_parser.close()
    return results

def generate_macro_graph(macros, output_path):
    G = nx.DiGraph()
    for macro in macros:
        vba_name = macro["vba_filename"]
        G.add_node(vba_name)
        G.add_edge("Document_Open", vba_name)
    plt.figure(figsize=(10, 6))
    nx.draw(G, with_labels=True, node_color="red", edge_color="gray", font_size=10)
    plt.savefig(output_path)

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
    file.save(filepath)

    clamav_result = subprocess.getoutput(f"clamscan {filepath}")
    yara_result = []
    if yara_rules:
        matches = yara_rules.match(filepath)
        yara_result = [str(match) for match in matches] if matches else ["No matches found."]
    else:
        yara_result = ["No rules loaded."]

    capa_output = subprocess.getoutput(f"capa {filepath}")

    oletools_result = analyze_office_file(filepath) if filename.endswith((".doc", ".docx", ".xls", ".xlsm", ".pptm", ".docm")) else None

    extracted_payloads = oletools_result.get("extracted_payloads", []) if oletools_result else []

    macro_graph_path = f"/app/static/{uuid.uuid4()}_macro_graph.png"
    if oletools_result and "vba_macros" in oletools_result:
        generate_macro_graph(oletools_result["vba_macros"], macro_graph_path)

    return render_template(
        "results.html",
        clamav_result=clamav_result,
        yara_result=yara_result,
        capa_result=capa_output,
        oletools_result=oletools_result,
        extracted_payloads=extracted_payloads,
        macro_graph_path=macro_graph_path if oletools_result else None
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
