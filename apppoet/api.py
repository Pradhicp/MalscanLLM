import os
import re
import json

def extract_api_calls(smali_folder):
    api_calls = []
    pattern = re.compile(r"invoke-\w+ \{[^\}]*\}, ([^\;]+);->([^\(]+)\(")

    for root, _, files in os.walk(smali_folder):
        for file in files:
            if file.endswith(".smali"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            match = pattern.search(line)
                            if match:
                                cls, method = match.groups()
                                api_calls.append(f"{cls}->{method}")
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")

    return api_calls


if __name__ == "__main__":
    base_folder = r"C:\Users\Pradheeba\LLM_Maldetect\mal"
    output_file = "api_calls.json"

    result = {}

    for root, dirs, files in os.walk(base_folder):
        if any(f.endswith(".smali") for f in files):
            apk_name = os.path.basename(root)
            features = extract_api_calls(root)
            result[apk_name] = features

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4)

    print(f"✅ API calls saved as JSON → {output_file}")
