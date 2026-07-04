# backend/intelligence/agentic_analyzer.py

import os
import json
from openai import OpenAI
from config import settings


class AgenticAnalyzer:
    def __init__(self):
        self.is_ready = False
        self.client = None

        api_key = settings.GROQ_API_KEY or os.environ.get("GROQ_API_KEY")
        if not api_key:
            return

        try:
            self.client = OpenAI(
                base_url=settings.GROQ_BASE_URL,
                api_key=api_key,
            )
            self.model = settings.GROQ_MODEL
            self.is_ready = True
        except Exception as e:
            print(f"  [AgenticAnalyzer] Init failed: {e}")
            self.is_ready = False

    def analyze_report(self, results, apk_path, jadx_dir, extracted_dir):
        if not self.is_ready:
            return {"error": "AI analyzer not ready"}

        # Build a concise summary of static findings for the model
        prompt = self._build_prompt(results)

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a senior Android malware analyst. "
                            "Analyze the forensic findings and respond ONLY with valid JSON."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                response_format={"type": "json_object"},
            )
            content = response.choices[0].message.content
            return json.loads(content)
        except Exception as e:
            return {"error": str(e)}

    def _build_prompt(self, results):
        apk_meta = results.get("apk_metadata", {})
        perms = results.get("permissions", {})
        iocs = results.get("iocs", {}).get("summary", {})
        code = results.get("code_analysis", {})
        packer = results.get("packer_analysis", {})
        nested = results.get("nested_analysis", {})

        summary = {
            "package": apk_meta.get("package_name"),
            "app_name": apk_meta.get("app_name"),
            "permissions_total": len(apk_meta.get("permissions", [])),
            "permission_risk": perms.get("risk_percentage"),
            "dangerous_combos": [c.get("name") for c in perms.get("dangerous_combinations", [])],
            "ioc_summary": iocs,
            "capabilities": [c.get("capability") for c in code.get("capabilities", [])],
            "code_risk_score": code.get("code_risk_score"),
            "is_packed": packer.get("is_packed"),
            "detected_packers": packer.get("detected_packers"),
            "dropper_confidence": nested.get("dropper_indicators", {}).get("dropper_confidence"),
        }

        return f"""
Analyze this Android APK forensic report and return a JSON object with EXACTLY these keys:
- "verdict": string (e.g. "MALICIOUS", "SUSPICIOUS", "BENIGN")
- "threat_score_override": integer 0-100
- "malware_family_hypothesis": string
- "executive_summary": string (2-3 sentences)
- "key_findings": JSON object/dictionary where each key is a short finding (summary) and each value is the corresponding detailed analysis (explanation)
- "mitre_attck_tactics": array of strings, specifically containing MITRE ATT&CK technique codes and names (e.g. "T1027: Obfuscated Files or Information", "T1059: Command and Scripting Interpreter")

FINDINGS:
{json.dumps(summary, indent=2, default=str)}
"""
