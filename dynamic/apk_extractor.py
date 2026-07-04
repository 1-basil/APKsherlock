import sys
import os

# Insert backend directory to sys.path so we can import test_analyzer
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../backend")))

def analyze_apk(apk_path):
    from test_analyzer import run_full_analysis
    
    # Run the proper static analysis only
    static_result = run_full_analysis(apk_path, static_only=True)
    
    # Extract apk metadata
    apk_meta = static_result.get('apk_metadata', {})
    
    # Signature
    cert_meta = static_result.get('certificate', {})
    sig_name = cert_meta.get('common_name', 'Unknown')
    signature = [sig_name] if sig_name else []
    
    # Permissions
    permissions_all = apk_meta.get('permissions', [])
    permissions_flagged = static_result.get('permissions', {}).get('dangerous', [])
    
    # Extract IOCs
    iocs_source = static_result.get('iocs', {}).get('iocs', {})
    
    iocs = {
        "ip": sorted(list({f.get('value') for f in iocs_source.get('ipv4_address', []) if f.get('value')})),
        "url": sorted(list({f.get('value') for f in iocs_source.get('url_full', []) if f.get('value')})),
        "domain": sorted(list({f.get('value') for f in iocs_source.get('domain', []) if f.get('value')})),
        "email": sorted(list({f.get('value') for f in iocs_source.get('email_address', []) if f.get('value')}))
    }
    
    return {
        "package_name": apk_meta.get('package_name', 'unknown'),
        "version": apk_meta.get('version_name', 'unknown'),
        "signature": signature,
        "permissions_all": permissions_all,
        "permissions_flagged": permissions_flagged,
        "iocs": iocs
    }
