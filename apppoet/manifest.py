import os
import xml.etree.ElementTree as ET
import json

def extract_manifest_features(manifest_path):
    features = []

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        # Extract permissions
        for perm in root.findall("uses-permission"):
            name = perm.attrib.get("{http://schemas.android.com/apk/res/android}name")
            if name:
                features.append(f"permission:{name}")

        # Extract receivers
        for receiver in root.iter("receiver"):
            name = receiver.attrib.get("{http://schemas.android.com/apk/res/android}name")
            if name:
                features.append(f"receiver:{name}")

        # Extract services
        for service in root.iter("service"):
            name = service.attrib.get("{http://schemas.android.com/apk/res/android}name")
            if name:
                features.append(f"service:{name}")

    except Exception as e:
        print(f"Error reading {manifest_path}: {e}")

    return features


if __name__ == "__main__":
    base_folder = r"C:\Users\Pradheeba\LLM_Maldetect\mal"
    output_file = "manifest_features.json"

    result = {}

    for root, dirs, files in os.walk(base_folder):
        if "AndroidManifest.xml" in files:
            apk_name = os.path.basename(root)
            manifest_path = os.path.join(root, "AndroidManifest.xml")
            features = extract_manifest_features(manifest_path)
            result[apk_name] = features

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4)

    print(f"✅ Manifest features saved as JSON → {output_file}")
