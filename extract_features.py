import os
import json
import glob
import xml.etree.ElementTree as ET

# --------- CONFIGURATION ---------
APK_DIR = r"C:\Users\Pradheeba\LLM_Maldetect\mal"  
FEATURES_OUT = r"C:\Users\Pradheeba\LLM_Maldetect\features\extracted_features_batch.json"

# --------- MANUAL LABELS ---------
# Example: assign 1 = malicious, 0 = benign
manual_labels = {
    "Adware_Beauty": 1,
    "bankers": 1,
    "CalculatorApp": 0
}

def get_label(apk_name):
    return manual_labels.get(apk_name, 0)  # default benign if not listed

# --------- FEATURE EXTRACTION FUNCTIONS ---------
def extract_permissions(manifest_path):
    permissions = []
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        for perm in root.findall("uses-permission"):
            name = perm.attrib.get("{http://schemas.android.com/apk/res/android}name")
            if name:
                permissions.append(name)
    except Exception as e:
        print(f"[!] Failed to parse permissions in {manifest_path}: {e}")
    return permissions

def extract_api_calls(smali_dir):
    api_calls = set()
    for root_dir, _, files in os.walk(smali_dir):
        for file in files:
            if file.endswith(".smali"):
                try:
                    with open(os.path.join(root_dir, file), 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            if line.strip().startswith("invoke") and '->' in line:
                                method = line.strip().split('->')[1].split('(')[0]
                                api_calls.add(method)
                except:
                    continue
    return list(api_calls)

def extract_strings(resources_path, smali_dir):
    strings = set()
    if os.path.exists(resources_path):
        try:
            tree = ET.parse(resources_path)
            root = tree.getroot()
            for s in root.findall("string"):
                if s.text:
                    strings.add(s.text)
        except:
            pass
    for root_dir, _, files in os.walk(smali_dir):
        for file in files:
            if file.endswith(".smali"):
                try:
                    with open(os.path.join(root_dir, file), 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            if 'const-string' in line:
                                parts = line.split(',')
                                if len(parts) > 1:
                                    s = parts[1].strip().strip('"')
                                    strings.add(s)
                except:
                    continue
    return list(strings)

# --------- MAIN EXTRACTION LOOP ---------
apk_folders = glob.glob(os.path.join(APK_DIR, "*"))
if not apk_folders:
    print(f"[!] No APK folders found in {APK_DIR}. Make sure you extracted them with Apktool.")
else:
    all_features = []
    for apk_path in apk_folders:
        manifest_path = os.path.join(apk_path, "AndroidManifest.xml")
        smali_dir = os.path.join(apk_path, "smali")
        resources_path = os.path.join(apk_path, "res", "values", "strings.xml")

        if not os.path.exists(manifest_path) or not os.path.exists(smali_dir):
            print(f"[!] Skipping {apk_path}, missing manifest or smali files.")
            continue

        apk_name = os.path.basename(apk_path)
        features = {
            "apk_name": apk_name,
            "permissions": extract_permissions(manifest_path),
            "api_calls": extract_api_calls(smali_dir),
            "strings": extract_strings(resources_path, smali_dir),
            "label": get_label(apk_name)  # ✅ MANUAL LABEL ASSIGNMENT
        }

        all_features.append(features)
        print(f"[+] Extracted features for {apk_path}")

    with open(FEATURES_OUT, 'w', encoding='utf-8') as f:
        json.dump(all_features, f, indent=2)

    print(f"\n[✓] Extraction completed. Total APKs processed: {len(all_features)}")
    print(f"[✓] Features saved to {FEATURES_OUT}")
