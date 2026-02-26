import os
import requests
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def check_gemini():
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("[!] GEMINI_API_KEY not found.")
        return

    print("\n--- Google Gemini Models ---")
    url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            models = data.get("models", [])
            found_any = False
            for m in models:
                name = m.get("name", "").replace("models/", "")
                methods = m.get("supportedGenerationMethods", [])
                if "generateContent" in methods:
                    print(f"  - {name}")
                    found_any = True
            if not found_any:
                print("  (No models found with 'generateContent' capability)")
        else:
            print(f"  [Error] Status {response.status_code}: {response.text}")
    except Exception as e:
        print(f"  [Exception] {e}")

def check_openai():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("[!] OPENAI_API_KEY not found.")
        return

    print("\n--- OpenAI Models (Checking Key) ---")
    url = "https://api.openai.com/v1/models"
    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            models = [m["id"] for m in data.get("data", [])]
            # Filter for interesting ones to avoid spam
            interesting = ["gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"]
            print(f"  [Success] Key is valid. Found {len(models)} models.")
            for i in interesting:
                if i in models:
                    print(f"  - {i}: AVAILABLE")
                else:
                    print(f"  - {i}: NOT FOUND")
        else:
            print(f"  [Error] Status {response.status_code}: {response.text}")
    except Exception as e:
        print(f"  [Exception] {e}")

def check_anthropic():
    api_key = os.getenv("CLAUDE_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("[!] CLAUDE_API_KEY / ANTHROPIC_API_KEY not found.")
        return

    print("\n--- Anthropic Claude (Probe) ---")
    # Anthropic doesn't have a public List Models endpoint. We must probe.
    models_to_test = [
        "claude-sonnet-4-5-20250929",
        "claude-3-7-sonnet-latest",
        "claude-3-7-sonnet-20250219",
        "claude-3-5-haiku-latest",
        "claude-3-5-haiku-20241022",
        "claude-3-haiku-20240307",
        "claude-3-5-sonnet-latest",
        "claude-3-opus-latest"
    ]
    
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
    }

    for model in models_to_test:
        data = {
            "model": model,
            "max_tokens": 10,
            "messages": [{"role": "user", "content": "Hello"}]
        }
        try:
            response = requests.post(url, headers=headers, json=data)
            if response.status_code == 200:
                print(f"  - {model}: AVAILABLE")
            elif response.status_code == 404: # Not Found Usually means invalid model ID
                 print(f"  - {model}: NOT FOUND (404)")
            elif response.status_code == 400: # Bad Request often means invalid model for this key tier
                 print(f"  - {model}: ERROR (400) - {response.text}")
            elif response.status_code == 401:
                 print(f"  - {model}: AUTH ERROR (401) - Check Key")
                 break # Key is bad, stop testing
            else:
                 print(f"  - {model}: Status {response.status_code}")
        except Exception as e:
            print(f"  - {model}: Exception {e}")

if __name__ == "__main__":
    print("Checking AI Model Availability...")
    check_gemini()
    check_openai()
    check_anthropic()
