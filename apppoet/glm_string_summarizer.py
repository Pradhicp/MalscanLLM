import json
import requests
import ijson
import time

API_KEY = '314757f7fad643aba5f70f1db174589d.PqqP11WL2eMP3jK3'  # your GLM API key
STRINGS_FILE = r'C:\Users\Pradheeba\LLM_Maldetect\features\extracted_features_batch.json'
OUTPUT_FILE = r'C:\Users\Pradheeba\LLM_Maldetect\features\string_summaries.jsonl'

# Open input and output files
with open(STRINGS_FILE, 'r', encoding='utf-8') as f, open(OUTPUT_FILE, 'w', encoding='utf-8') as out_f:
    
    # Iterate over each APK object in the JSON array
    for apk in ijson.items(f, 'item'):
        apk_id = apk.get('apk_id', apk.get('apk_name', 'unknown_apk'))
        strings = apk.get('strings', [])

        if not strings:
            continue  # skip APKs with no strings

        prompt = (
            f"Summarize the behavior of the following Android app based on its strings.  "
            f"Mention any permissions, network activity, or sensitive actions, without assuming the app is malicious.\n\n{', '.join(strings)}"
        )

        try:
            response = requests.post(
                "https://open.bigmodel.cn/api/paas/v4/chat/completions",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {API_KEY}"
                },
                json={
                    "model": "glm-4-flash",  # updated model name
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.5
                },
                timeout=30  # 30 seconds timeout
            )

            if response.status_code == 200:
                summary = response.json()["choices"][0]["message"]["content"]
            else:
                summary = f"[!] API call failed: {response.status_code} - {response.text}"

        except requests.exceptions.Timeout:
            summary = "[!] API call timed out."
        except requests.exceptions.RequestException as e:
            summary = f"[!] Request failed: {e}"

        # Write output as JSONL
        json_line = json.dumps({"apk_id": apk_id, "summary": summary}, ensure_ascii=False)
        out_f.write(json_line + "\n")

        print(f"[+] Summary saved for {apk_id}")

        # Optional: wait 1 second between requests to avoid rate limits
        time.sleep(1)
