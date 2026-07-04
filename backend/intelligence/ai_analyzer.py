import os
import json
import traceback
import time

class AIAnalyzer:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get('GEMINI_API_KEY')
        self.client = None

        if self.api_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                # Using standard Gemini 2.5 Flash for detailed context parsing
                self.model = genai.GenerativeModel('gemini-2.5-flash')
                self.client = True
            except ImportError:
                print("    ⚠️  google-generativeai not installed. Run: pip install google-generativeai")
            except Exception as e:
                print(f"    ⚠️  Failed to initialize AI model: {e}")

    def analyze_report(self, report_data: dict) -> dict:
        """
        Takes the complete forensic_report.json dictionary and passes it to the LLM.
        """
        if not self.client:
            return {"error": "AI client not initialized (missing API key or package)."}

        # Truncate overly long sections if needed to avoid token limit explosions,
        # although Gemini 1.5 has a 1-2M token window, we want to be efficient.
        safe_data = self._prepare_data_for_llm(report_data)
        json_str = json.dumps(safe_data, indent=2)

        prompt = f"""
You are a Senior Malware Reverse Engineer and Threat Intelligence Analyst. 
Review the following automated static analysis report for an Android application.

Focus on:
1. Identifying if the app is malicious, a grayware/adware app, or benign.
2. Explaining the likely true intent of the application (e.g., Banking Trojan, Spyware, Dropper, Fake App).
3. Analyzing any Command and Control (C2) infrastructure or suspicious URLs/domains.
4. Analyzing permission abuse and dangerous code capabilities.
5. If nested APKs or hidden payloads were found, assess if this represents a multi-stage infection chain.

Output your response STRICTLY as a JSON object matching this schema:
{{
    "threat_score_override": <int 0-100>,
    "verdict": "<SAFE | SUSPICIOUS | MALICIOUS>",
    "malware_family_hypothesis": "<string, or null if unknown/none>",
    "executive_summary": "<string, a cohesive 2-3 paragraph explanation of the app's behavior>",
    "key_findings": [
        "<string finding 1>",
        "<string finding 2>"
    ],
    "mitre_attck_tactics": [
        "<string tactic 1 (e.g. T1629)>"
    ]
}}

Here is the raw forensic data:
```json
{json_str}
```
"""

        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = self.model.generate_content(
                    prompt,
                    generation_config={"response_mime_type": "application/json"}
                )
                
                # Parse the JSON response
                result_json = response.text.strip()
                if result_json.startswith('```json'):
                    result_json = result_json[7:]
                if result_json.startswith('```'):
                    result_json = result_json[3:]
                if result_json.endswith('```'):
                    result_json = result_json[:-3]
                
                return json.loads(result_json.strip())
                
            except json.JSONDecodeError as e:
                print(f"    [*] Gemini returned malformed JSON. Retrying... ({attempt+1}/{max_retries})")
                if attempt == max_retries - 1:
                    return {"error": f"LLM generated invalid JSON: {str(e)}"}
            except Exception as e:
                if '429' in str(e) and attempt < max_retries - 1:
                    # Implement exponential backoff for 429 rate limit
                    wait = (2 ** attempt) * 60  # 60s, 120s, 240s
                    print(f"    [*] Gemini Rate limited (429). Waiting {wait}s before retry...")
                    time.sleep(wait)
                else:
                    traceback.print_exc()
                    return {"error": f"LLM generation failed: {str(e)}"}

    def _prepare_data_for_llm(self, data: dict) -> dict:
        """
        Reduces the size of the JSON payload by truncating massive lists
        (e.g., thousands of strings or files) while preserving critical metadata.
        """
        # Deep copy to avoid mutating the original report
        import copy
        safe_data = copy.deepcopy(data)

        # Truncate files list if it exists
        if 'file_tree' in safe_data.get('extraction', {}):
            safe_data['extraction']['file_tree'] = "[TRUNCATED - Too many files]"

        # Truncate strings if present
        if 'strings' in safe_data.get('iocs', {}):
            safe_data['iocs']['strings'] = "[TRUNCATED]"

        # Keep only the top 10 URLs/Domains
        if 'network' in safe_data.get('iocs', {}):
            for net_type in ['urls', 'domains', 'ips']:
                if net_type in safe_data['iocs']['network']:
                    safe_data['iocs']['network'][net_type] = safe_data['iocs']['network'][net_type][:10]
                    
        # Severely truncate the static decompiled output
        if 'decompiled' in safe_data:
            safe_data['decompiled'] = "[TRUNCATED - Too large for AI context]"
            
        # Truncate strings output
        if 'strings' in safe_data.get('iocs', {}):
             safe_data['iocs']['strings'] = "[TRUNCATED - Too large for AI context]"

        return safe_data
