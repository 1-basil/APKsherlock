import json
import urllib.request
import urllib.error

class VirusTotalClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"

    async def check_hash(self, file_hash: str) -> dict:
        """
        Check a file hash against VirusTotal v3 API.
        This uses asyncio, but we'll do a synchronous urllib request wrapped in an async method for simplicity.
        """
        if not file_hash or file_hash == 'N/A':
            return {"error": "Invalid or missing hash"}

        url = f"{self.base_url}/files/{file_hash}"
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        
        try:
            # We are using synchronous urllib here but returning async to match signature
            import urllib.request
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as response:
                body = response.read().decode("utf-8")
                data = json.loads(body)
                
                # Parse VT response
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                results = data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = sum(stats.values())
                
                scans = {}
                # Only keep positive hits to save space
                for engine, res in results.items():
                    if res.get('category') in ['malicious', 'suspicious']:
                        scans[engine] = {
                            "detected": True,
                            "result": res.get('result')
                        }
                
                return {
                    "hash": file_hash,
                    "positives": malicious + suspicious,
                    "total": total,
                    "scans": scans
                }
                
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"error": "Not found in VirusTotal"}
            elif e.code == 401:
                return {"error": "Invalid VirusTotal API Key"}
            elif e.code == 429:
                return {"error": "VirusTotal API rate limit exceeded"}
            else:
                return {"error": f"HTTP Error {e.code}"}
        except Exception as e:
            return {"error": str(e)}
