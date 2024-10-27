# scanners/yara_scanner.py
import yara

def compile_rules(rule_paths):
    rules = yara.compile(filepaths=rule_paths)
    return rules

def scan_file(rules, file_path):
    matches = rules.match(file_path)
    if matches:
        return {'status': 'match', 'details': [match.rule for match in matches]}
    else:
        return {'status': 'clean', 'details': []}