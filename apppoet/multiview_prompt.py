import os
import json

# ===========================================
# CONFIGURATION
# ===========================================
MANIFEST_FEATURES_FILE = r"C:\Users\Pradheeba\LLM_Maldetect\manifest_features.json"
API_CALLS_FILE = r"C:\Users\Pradheeba\LLM_Maldetect\api_calls.json"
STRING_FEATURES_FILE = r"C:\Users\Pradheeba\LLM_Maldetect\features\string_summaries.jsonl"

OUTPUT_FILE = r"C:\Users\Pradheeba\LLM_Maldetect\apk_labels.jsonl"

# ===========================================
# HELPER FUNCTIONS
# ===========================================
def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {}

def read_jsonl(path):
    data = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                js = json.loads(line.strip())
                apk_name = js.get("apk_id") or js.get("apk_name") or js.get("name") or f"apk_{len(data)}"
                features = js.get("features") or js.get("strings") or []
                data[apk_name] = features
    except:
        pass
    return data

def summarize_view(features, top_n=5):
    return features[:top_n] if features else []

def detect_label(manifest_features, api_features, string_features):
    """
    Improved heuristic to detect if APK is malicious.
    Returns 'Malicious' or 'Benign'
    """
    malicious_permissions = {
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.INTERNET",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION"
    }

    malicious_api_calls = {
        "exec", "loadLibrary", "getDeviceId", "getSubscriberId",
        "Runtime.getRuntime", "System.loadLibrary", "sendTextMessage"
    }

    malicious_strings_keywords = {
        "http://", "https://", "malware", "attack", "payload", "keylogger",
        "trojan", "spyware", "phishing", "ransomware"
    }

    score = 0

    # Count malicious permissions
    perm_hits = sum(1 for p in manifest_features if any(mp.lower() in p.lower() for mp in malicious_permissions))
    score += perm_hits

    # Count malicious API calls
    api_hits = sum(1 for a in api_features if any(ma.lower() in a.lower() for ma in malicious_api_calls))
    score += api_hits

    # Count malicious string indicators
    string_hits = sum(1 for s in string_features if any(k.lower() in s.lower() for k in malicious_strings_keywords))
    score += string_hits

    # Threshold logic: if any hits found, mark as malicious
    return "Malicious" if score > 0 else "Benign"

# ===========================================
# LOAD FEATURE FILES
# ===========================================
manifest_data = read_json(MANIFEST_FEATURES_FILE)
api_data = read_json(API_CALLS_FILE)
string_data = read_jsonl(STRING_FEATURES_FILE)

apk_names = set(manifest_data.keys()) | set(api_data.keys()) | set(string_data.keys())

# ===========================================
# GENERATE MULTIVIEW PROMPTS WITH LABELS
# ===========================================
with open(OUTPUT_FILE, "w", encoding="utf-8") as out_f:
    for apk in sorted(apk_names):
        manifest_features = manifest_data.get(apk, [])
        api_features = api_data.get(apk, [])
        string_features = string_data.get(apk, [])

        manifest_summary = summarize_view(manifest_features)
        api_summary = summarize_view(api_features)
        string_summary = summarize_view(string_features)

        label = detect_label(manifest_features, api_features, string_features)

        # Build multiview textual representation
        multiview_text = "You are a cybersecurity analyst analyzing Android applications.\n\n"
        multiview_text += f"[Manifest View]\nFeatures: {', '.join(manifest_features[:20])}\n"
        if manifest_summary:
            multiview_text += f"Summary: {', '.join(manifest_summary)}\n"
        multiview_text += "\n"

        multiview_text += f"[API Call View]\nFeatures: {', '.join(api_features[:20])}\n"
        if api_summary:
            multiview_text += f"Summary: {', '.join(api_summary)}\n"
        multiview_text += "\n"

        multiview_text += f"[String View]\nFeatures: {', '.join(string_features[:20])}\n"
        if string_summary:
            multiview_text += f"Summary: {', '.join(string_summary)}\n"
        multiview_text += "\n"

        multiview_text += f"[App Summary View]\nSummary: Extracted from APK {apk}.\n"
        multiview_text += "Based on this data, classify the app as 'Malicious' or 'Benign'."

        out_entry = {
            "instruction": "Classify the Android app based on the following enriched multiview representation.",
            "input": multiview_text,
            "output": label,
            "_meta": {"apk_name": apk}
        }

        out_f.write(json.dumps(out_entry, ensure_ascii=False) + "\n")

print(f"✅ Multiview prompts created for {len(apk_names)} APKs.")
print(f"📄 Output written to: {OUTPUT_FILE}")
