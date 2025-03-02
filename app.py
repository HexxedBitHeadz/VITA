from flask import Flask, render_template, request, redirect, url_for
from oletools.olevba import VBA_Parser
from oletools.oleid import OleID
import networkx as nx, matplotlib.pyplot as plt, yara, subprocess, os, shutil, threading, re, base64, time, oletools.mraptor

app = Flask(__name__)
UPLOAD_FOLDER = '/app/uploads'
RULES_FOLDER = '/app/yara-rules/packages/full/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Load YARA rules
def load_yara_rules():
    rule_files = {}
    for root, _, files in os.walk(RULES_FOLDER):
        for file in files:
            if file.endswith('.yar') or file.endswith('.yara'):
                rule_path = os.path.join(root, file)
                rule_files[file] = rule_path
    print(f"Loaded YARA rules: {list(rule_files.keys())}")
    return yara.compile(filepaths=rule_files)

# Preload rules at startup
try:
    yara_rules = load_yara_rules()
except yara.SyntaxError as e:
    print(f"Error loading YARA rules: {e}")
    yara_rules = None

def reload_yara_rules():
    global yara_rules
    time.sleep(600)  # Wait 10 minutes before first reload
    while True:
        try:
            yara_rules = load_yara_rules()
            print("YARA rules updated successfully!")
        except yara.SyntaxError as e:
            print(f"Error updating YARA rules: {e}")
        time.sleep(600)  # Refresh every 10 minutes

# Start the YARA reloader
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
                continue  # Ignore invalid decoding errors

    return payloads

def analyze_office_file(filepath):
    results = {}

    oid = OleID(filepath)
    indicators = oid.check()
    results['oleid'] = {
        str(i.id): str(i.value.decode(errors="ignore") if isinstance(i.value, bytes) else i.value)
        for i in indicators
    }

    vba_parser = VBA_Parser(filepath)
    if vba_parser.detect_vba_macros():
        results['vba_macros'] = []
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

        results["extracted_payloads"] = extract_payloads(results["vba_macros"])

    vba_parser.close()
    return results
    
def generate_macro_graph(macros):
    """Creates a visualization of macro execution relationships."""
    G = nx.DiGraph()

    for macro in macros:
        vba_name = macro["vba_filename"]
        code_snippet = macro["vba_code_snippet"][:50]  # Limit size

        G.add_node(vba_name, label=vba_name)
        G.add_edge("Document_Open", vba_name)

    # Save graph as an image
    plt.figure(figsize=(10, 6))
    nx.draw(G, with_labels=True, node_color="red", edge_color="gray", font_size=10)
    plt.savefig("/app/static/macro_graph.png")

def format_oletools_results(oletools_result, file_name="Unknown"):
    if not oletools_result:
        return "No OLETools results available."

    output = []
    output.append("=" * 80)
    output.append(f"FILE: {file_name}")  
    output.append(f"Type: {oletools_result.get('oleid', {}).get('ftype', 'Unknown')}")
    output.append("=" * 80)
    output.append("")

    table_headers = ["Indicator", "Value", "Risk", "Description"]
    #column_widths = [25, 45, 10, 35]
    column_widths = [25, 55, 10, 40] 


    output.append(" | ".join(h.ljust(w) for h, w in zip(table_headers, column_widths)))
    output.append("-" * sum(column_widths))

    fields = [
        ("File format", oletools_result["oleid"].get("ftype", "N/A"), "info", "File type detected"),
        ("Container format", oletools_result["oleid"].get("container", "N/A"), "info", "File container format"),
        ("Application name", oletools_result["oleid"].get("appname", "N/A"), "info", "Declared application"),
        ("Properties code page", oletools_result["oleid"].get("codepage", "N/A"), "info", "Encoding of properties"),
        ("Author", oletools_result["oleid"].get("author", "N/A"), "info", "Declared author"),
        ("Encrypted", str(oletools_result["oleid"].get("encrypted", "N/A")), "none", "Encryption status"),
        ("VBA Macros", oletools_result["oleid"].get("vba", "N/A"), "HIGH", "Macro presence"),
        ("XLM Macros", oletools_result["oleid"].get("xlm", "N/A"), "none", "Excel 4/XLM macros"),
        ("External Rels", str(oletools_result["oleid"].get("ext_rels", "N/A")), "none", "External relationships"),
    ]

    for field in fields:
        output.append(" | ".join(str(f).ljust(w) for f, w in zip(field, column_widths)))

    output.append("-" * sum(column_widths))
    output.append("")

    # Add VBA Macros section
    if oletools_result.get("vba_macros"):
        output.append("VBA MACROS DETECTED:")
        output.append("-" * 80)
        for macro in oletools_result["vba_macros"]:
            output.append(f"VBA MACRO {macro['vba_filename']}")
            output.append(f"in file: {macro['filename']} - OLE stream: {macro['stream_path']}")
            output.append("-" * 80)
            output.append(macro["vba_code_snippet"])
            output.append("-" * 80)

    if oletools_result.get("macro_dangerous"):
        output.append("WARNING: Suspicious Macro Detected!")
    else:
        output.append("No suspicious macros found.")

    # **New Feature: Display Extracted Payloads**
    if oletools_result.get("extracted_payloads"):
        output.append("\nExtracted Payloads:")
        output.append("-" * 80)
        # for payload in oletools_result["extracted_payloads"]:
        #     output.append(payload[:500] + ("..." if len(payload) > 500 else ""))  # Truncate for readability
        # output.append("-" * 80)

    return "\n".join(output)

@app.route("/")
def upload():
    return render_template("upload.html")


@app.route("/", methods=["POST"])
def handle_upload():
    if "file" not in request.files:  # Ensure file exists in the request
        return "No file part", 400

    file = request.files["file"]
    if file.filename == "":  # Handle empty file uploads
        return "No selected file", 400

    filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    file.save(filepath)

    clamav_result = subprocess.getoutput(f"clamscan {filepath}")
    yara_result = "No rules loaded." if not yara_rules else [str(match) for match in yara_rules.match(filepath)]

    capa_output = "Skipped CAPA for Office documents."
    if not file.filename.endswith((".doc", ".docx", ".xls", ".xlsm", ".pptm", ".docm")):
        try:
            capa_output = subprocess.getoutput(f"capa {filepath}")
        except Exception as e:
            capa_output = f"Error running CAPA: {e}"

    oletools_result = None
    if file.filename.endswith((".doc", ".docx", ".xls", ".xlsm", ".pptm", ".docm")):
        oletools_result = analyze_office_file(filepath)

    if oletools_result and "vba_macros" in oletools_result:
        generate_macro_graph(oletools_result["vba_macros"])

    extracted_payloads = []
    if oletools_result and "vba_macros" in oletools_result:
        extracted_payloads = extract_payloads(oletools_result["vba_macros"])
        with open(f"/app/uploads/{file.filename}_payloads.txt", "w") as f:
            f.write("\n".join(extracted_payloads))

    pdf_scan_output, archive_extracted = "N/A", "N/A"
    if file.filename.endswith(".pdf"):
        pdf_scan_output = subprocess.getoutput(f"pdfid {filepath}")
    elif file.filename.endswith((".zip", ".rar", ".7z")):
        extract_path = os.path.join("/app/uploads/", "extracted")
        os.makedirs(extract_path, exist_ok=True)
        subprocess.run(f"unzip {filepath} -d {extract_path}", shell=True)
        archive_extracted = f"Files extracted to {extract_path}"

    return render_template(
        "results.html",
        clamav_result=clamav_result,
        yara_result=yara_result,
        capa_result=capa_output,
        oletools_result=format_oletools_results(oletools_result, file_name=file.filename) if oletools_result else "Not an Office document.",
        extracted_payloads=extracted_payloads,
    )
    
    #return redirect(url_for("upload"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
