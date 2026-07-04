# backend/test_analyzer.py

import sys
import os
import json
import time
from pathlib import Path
from datetime import datetime

# ─── Add backend to path ─────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def print_section(title: str, char: str = "="):
    width = 70
    print(f"\n{'='*width}")
    print(f"  {title}")
    print(f"{'='*width}")

def print_subsection(title: str):
    print(f"\n  {'─'*60}")
    print(f"  ▶  {title}")
    print(f"  {'─'*60}")

def print_json(data, indent: int = 2):
    """Safe JSON printer that handles non-serializable objects"""
    def default_handler(obj):
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        return str(obj)
    print(json.dumps(data, indent=indent, default=default_handler))

def print_finding(severity: str, message: str):
    """Print color-coded findings"""
    icons = {
        "CRITICAL": "🔴 [CRITICAL]",
        "HIGH":     "🟠 [HIGH]",
        "MEDIUM":   "🟡 [MEDIUM]",
        "LOW":      "🟢 [LOW]",
        "INFO":     "🔵 [INFO]",
        "OK":       "✅ [OK]",
        "WARN":     "⚠️  [WARN]",
        "ERROR":    "❌ [ERROR]",
    }
    icon = icons.get(severity, f"[{severity}]")
    print(f"    {icon} {message}")

def run_full_analysis(apk_path: str):
    """
    Complete forensic analysis pipeline
    Tests every module and shows detailed output
    """
    if not os.path.exists(apk_path):
        print(f"❌ File not found: {apk_path}")
        sys.exit(1)

    apk_path   = os.path.abspath(apk_path)
    apk_name   = os.path.basename(apk_path)
    output_dir = os.path.join(
        os.path.dirname(apk_path),
        f"analysis_{Path(apk_name).stem}_{int(time.time())}"
    )
    os.makedirs(output_dir, exist_ok=True)

    print_section("FORENSICDROID - APK FORENSIC ANALYSIS SYSTEM")
    print(f"  Target  : {apk_name}")
    print(f"  Path    : {apk_path}")
    print(f"  Output  : {output_dir}")
    print(f"  Time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    results = {}

    # ══════════════════════════════════════════════════════════
    # MODULE 1: File Metadata & Hashes
    # ══════════════════════════════════════════════════════════
    print_section("MODULE 1: FILE METADATA & FORENSIC HASHES")
    try:
        import hashlib
        stat = os.stat(apk_path)
        hashes = {}

        with open(apk_path, 'rb') as f:
            data           = f.read()
            hashes['md5']    = hashlib.md5(data).hexdigest()
            hashes['sha1']   = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
            hashes['sha512'] = hashlib.sha512(data).hexdigest()

        file_meta = {
            "filename":    apk_name,
            "size_bytes":  stat.st_size,
            "size_mb":     round(stat.st_size / 1024 / 1024, 2),
            "hashes":      hashes,
            "analyzed_at": datetime.utcnow().isoformat() + "Z"
        }

        print_finding("OK",   f"File size  : {file_meta['size_mb']} MB")
        print_finding("INFO", f"MD5        : {hashes['md5']}")
        print_finding("INFO", f"SHA1       : {hashes['sha1']}")
        print_finding("INFO", f"SHA256     : {hashes['sha256']}")

        results['file_metadata'] = file_meta
        print("\n  ✅ Module 1 PASSED")

    except Exception as e:
        print(f"  ❌ Module 1 FAILED: {e}")
        import traceback; traceback.print_exc()

    # ══════════════════════════════════════════════════════════
    # MODULE 2: APK Extraction & File Tree
    # ══════════════════════════════════════════════════════════
    print_section("MODULE 2: APK EXTRACTION & FILE TREE")
    try:
        import zipfile

        file_tree    = []
        suspicious   = []
        native_libs  = []
        dex_files    = []
        asset_files  = []

        with zipfile.ZipFile(apk_path, 'r') as zf:
            all_files = zf.infolist()
            print_finding("INFO", f"Total files in APK: {len(all_files)}")

            for info in all_files:
                ext  = Path(info.filename).suffix.lower()
                entry = {
                    "path":       info.filename,
                    "size":       info.file_size,
                    "compressed": info.compress_size,
                    "type":       _classify_file(info.filename),
                    "suspicious": _is_suspicious(info.filename),
                    "flag":       _get_flag(info.filename)
                }
                file_tree.append(entry)

                if entry["suspicious"]:
                    suspicious.append(info.filename)
                if ext == ".so":
                    native_libs.append(info.filename)
                if ext == ".dex":
                    dex_files.append(info.filename)
                if "assets/" in info.filename:
                    asset_files.append(info.filename)

        print_finding("INFO",  f"DEX files      : {len(dex_files)}")
        print_finding("INFO",  f"Native libs    : {len(native_libs)}")
        print_finding("INFO",  f"Asset files    : {len(asset_files)}")

        if suspicious:
            print_finding("HIGH", f"Suspicious files found: {len(suspicious)}")
            for s in suspicious[:5]:
                print(f"           → {s}")

        if native_libs:
            print_finding("MEDIUM", f"Native libraries: {native_libs}")

        print_subsection("DEX Files (Bytecode)")
        for d in dex_files:
            print(f"    📦 {d}")

        print_subsection("Native Libraries (.so)")
        for n in native_libs:
            print(f"    🔧 {n}")

        print_subsection("Asset Files (first 10)")
        for a in asset_files[:10]:
            print(f"    📄 {a}")

        results['file_tree']   = file_tree
        results['native_libs'] = native_libs
        results['dex_files']   = dex_files
        print("\n  ✅ Module 2 PASSED")

    except Exception as e:
        print(f"  ❌ Module 2 FAILED: {e}")
        import traceback; traceback.print_exc()

    # ══════════════════════════════════════════════════════════
    # MODULE 2.5: JADX Decompilation
    # ══════════════════════════════════════════════════════════
    print_section("MODULE 2.5: JADX DECOMPILATION (JAVA SOURCE)")
    try:
        from analyzer.static.jadx_extractor import JadxExtractor
        extractor = JadxExtractor(apk_path, output_dir)
        java_files = extractor.decompile()
        
        print_finding("INFO", f"Extracted Java files : {len(java_files)}")
        if java_files:
            print_subsection("Sample Java Files (first 3)")
            for i, p in enumerate(list(java_files.keys())[:3]):
                print(f"    ☕ {p}")
                
        results['decompiled'] = {'java_files': java_files}
        print("\n  ✅ Module 2.5 PASSED")
        
    except Exception as e:
        print(f"  ❌ Module 2.5 FAILED: {e}")
        print("  ⚠️ Proceeding without decompiled Java source code.")

    # ══════════════════════════════════════════════════════════
    # MODULE 3: Androguard - Core APK Analysis
    # ══════════════════════════════════════════════════════════
    print_section("MODULE 3: ANDROGUARD - DEEP APK ANALYSIS")
    apk_obj = None
    dx_obj  = None

    try:
        import warnings
        warnings.filterwarnings('ignore')
        from androguard.misc import AnalyzeAPK

        print("  [*] Loading APK with Androguard (may take 30-60 seconds)...")
        t_start = time.time()
        a, d, dx = AnalyzeAPK(apk_path)
        t_end   = time.time()
        print(f"  [*] Loaded in {t_end - t_start:.1f} seconds")

        apk_obj = a
        dx_obj  = dx

        apk_meta = {
            "package_name":    a.get_package(),
            "app_name":        a.get_app_name(),
            "version_name":    a.get_androidversion_name(),
            "version_code":    a.get_androidversion_code(),
            "min_sdk":         a.get_min_sdk_version(),
            "target_sdk":      a.get_target_sdk_version(),
            "is_valid_apk":    a.is_valid_APK(),
            "permissions":     list(a.get_permissions()),
            "activities":      list(a.get_activities()),
            "services":        list(a.get_services()),
            "receivers":       list(a.get_receivers()),
            "providers":       list(a.get_providers()),
            "declared_perms":  list(a.get_declared_permissions()),
            "libraries":       list(a.get_libraries()),
            "main_activity":   a.get_main_activity(),
        }

        print_finding("INFO",   f"Package     : {apk_meta['package_name']}")
        print_finding("INFO",   f"App Name    : {apk_meta['app_name']}")
        print_finding("INFO",   f"Version     : {apk_meta['version_name']} (code: {apk_meta['version_code']})")
        print_finding("INFO",   f"SDK Range   : {apk_meta['min_sdk']} → {apk_meta['target_sdk']}")
        print_finding("INFO",   f"Activities  : {len(apk_meta['activities'])}")
        print_finding("INFO",   f"Services    : {len(apk_meta['services'])}")
        print_finding("INFO",   f"Receivers   : {len(apk_meta['receivers'])}")
        print_finding("INFO",   f"Permissions : {len(apk_meta['permissions'])}")

        results['apk_metadata'] = apk_meta
        print("\n  ✅ Module 3 PASSED")

    except ImportError:
        print("  ❌ Androguard not installed!")
        print("  ⚠️ Run: pip install androguard==3.3.3 lxml cryptography")
    except Exception as e:
        if "compression method is not supported" in str(e) or isinstance(e, NotImplementedError):
            print("  [*] Unsupported compression detected (Packer trick). Attempting to repack APK...")
            try:
                import zipfile
                import shutil
                fixed_path = apk_path.replace('.apk', '_fixed.apk')
                extract_dir = apk_path + "_extracted"
                os.makedirs(extract_dir, exist_ok=True)
                
                with zipfile.ZipFile(apk_path, 'r') as z:
                    for item in z.infolist():
                        try:
                            data = z.read(item.filename)
                            out_path = os.path.join(extract_dir, item.filename)
                            os.makedirs(os.path.dirname(out_path), exist_ok=True)
                            with open(out_path, 'wb') as f:
                                f.write(data)
                        except Exception:
                            pass
                            
                with zipfile.ZipFile(fixed_path, 'w', zipfile.ZIP_DEFLATED) as zout:
                    for root, dirs, files in os.walk(extract_dir):
                        for file in files:
                            full_path = os.path.join(root, file)
                            arcname = os.path.relpath(full_path, extract_dir)
                            zout.write(full_path, arcname)
                            
                shutil.rmtree(extract_dir)
                print("  [*] Repack successful. Retrying Androguard...")
                
                a, d, dx = AnalyzeAPK(fixed_path)
                
                apk_name = a.get_app_name()
                package_name = a.get_package()
                results['apk_metadata'] = {
                    'app_name':     apk_name,
                    'package_name': package_name,
                    'version_name': a.get_version_name(),
                    'version_code': a.get_version_code(),
                    'min_sdk':      a.get_min_sdk_version(),
                    'target_sdk':   a.get_target_sdk_version(),
                    'permissions':  a.get_permissions()
                }
                
                print_finding("INFO", f"App Name     : {apk_name}")
                print_finding("INFO", f"Package      : {package_name}")
                print_finding("INFO", f"Version      : {a.get_version_name()} ({a.get_version_code()})")
                print("\n  ✅ Module 3 PASSED (via repacking)")
                
                # Keep fixed_path for Module 5 & 7
                apk_path = fixed_path
                
            except Exception as repack_e:
                print(f"  ❌ Repack failed: {repack_e}")
                print("  ⚠️ On Windows, Androguard can be tricky. Ensure you ran: pip install -r requirements.txt")
        else:
            print(f"  ❌ Module 3 FAILED: {e}")
            print("  ⚠️ On Windows, Androguard can be tricky. Ensure you ran: pip install -r requirements.txt")
            import traceback; traceback.print_exc()

    # ══════════════════════════════════════════════════════════
    # MODULE 4: Permission Analysis
    # ══════════════════════════════════════════════════════════
    print_section("MODULE 4: PERMISSION RISK ANALYSIS")
    try:
        from analyzer.static.permission_analyzer import PermissionAnalyzer

        perms    = results.get('apk_metadata', {}).get('permissions', [])
        analyzer = PermissionAnalyzer(perms)
        perm_result = analyzer.analyze()

        print_finding("INFO",  f"Total permissions : {perm_result['total_permissions']}")
        print_finding("INFO",  f"Risk grade        : {perm_result['risk_grade']}")
        print_finding("INFO",  f"Risk score        : {perm_result['risk_percentage']}%")

        cat = perm_result.get('categorized', {})
        if cat.get('CRITICAL'):
            print_finding("CRITICAL", f"Critical permissions ({len(cat['CRITICAL'])}):")
            for p in cat['CRITICAL']:
                print(f"             → {p}")

        if cat.get('DANGEROUS'):
            print_finding("HIGH", f"Dangerous permissions ({len(cat['DANGEROUS'])}):")
            for p in cat['DANGEROUS']:
                print(f"             → {p}")

        combos = perm_result.get('dangerous_combinations', [])
        if combos:
            print_finding("CRITICAL",
                f"DANGEROUS COMBINATIONS DETECTED: {len(combos)}")
            for combo in combos:
                print(f"\n    ⚡ {combo['name']} [{combo['severity']}]")
                print(f"       {combo['forensic_significance'][:100]}...")
                print(f"       Matched: {combo.get('match_percentage', 0)}%")
        else:
            print_finding("OK", "No dangerous permission combinations")

        results['permissions'] = perm_result
        print("\n  ✅ Module 4 PASSED")

    except Exception as e:
        print(f"  ❌ Module 4 FAILED: {e}")
        import traceback; traceback.print_exc()

    # ══════════════════════════════════════════════════════════
    # MODULE 5: Certificate Analysis
    # ══════════════════════════════════════════════════════════
    print_section("MODULE 5: SIGNING CERTIFICATE & DEVELOPER IDENTITY")
    try:
        from analyzer.static.certificate_analyzer import CertificateAnalyzer

        if apk_obj:
            cert_analyzer = CertificateAnalyzer(apk_obj)
            cert_result   = cert_analyzer.analyze()

            if cert_result.get('certificates'):
                cert = cert_result['certificates'][0]
                subject = cert.get('subject', {})

                print_finding("INFO",
                    f"Developer   : {subject.get('common_name', 'Unknown')}")
                print_finding("INFO",
                    f"Org         : {subject.get('organization', 'Unknown')}")
                print_finding("INFO",
                    f"Country     : {subject.get('country', 'Unknown')}")
                print_finding("INFO",
                    f"Email       : {subject.get('email', 'Not found')}")
                print_finding("INFO",
                    f"Valid until : {cert.get('validity', {}).get('not_after')}")
                print_finding("INFO",
                    f"Signing     : {cert_result.get('signing_scheme')}")
                print_finding("INFO",
                    f"Self-signed : {cert_result.get('is_self_signed')}")
                print_finding("INFO",
                    f"Debug cert  : {cert_result.get('is_debug_signed')}")

                sha256 = cert.get('hashes', {}).get('sha256', 'N/A')
                print_finding("INFO", f"SHA256 FP   : {sha256}")

                attr = cert_result.get('attribution_clues', {})
                notes = attr.get('investigation_notes', [])
                if notes:
                    print_subsection("Investigation Notes")
                    for note in notes:
                        print(f"    📌 {note}")

                if cert_result.get('is_debug_signed'):
                    print_finding("HIGH",
                        "DEBUG CERTIFICATE - App was not properly signed!")
                if cert_result.get('is_self_signed'):
                    print_finding("MEDIUM",
                        "Self-signed certificate - not from trusted CA")

            results['certificate'] = cert_result
            print("\n  ✅ Module 5 PASSED")
        else:
            print("  ⚠️  Skipped - Androguard not loaded")

    except Exception as e:
        print(f"  ❌ Module 5 FAILED: {e}")
        import traceback; traceback.print_exc()

    # ══════════════════════════════════════════════════════════
    # MODULE 6: IOC Extraction
    # ══════════════════════════════════════════════════════════
    print_section("MODULE 6: IOC EXTRACTION - IPs, DOMAINS, KEYS, WALLETS")
    try:
        from analyzer.static.ioc_extractor import IOCExtractor

        java_files = results.get('decompiled', {}).get('java_files', {})
        raw_strings = _extract_raw_strings(apk_path)
        string_blob = "\n".join(raw_strings)
        if string_blob:
            java_files["__strings_dump__"] = string_blob

        ioc_extractor = IOCExtractor(java_files)
        ioc_result    = ioc_extractor.extract_all()

        summary = ioc_result.get('summary', {})
        print_finding("INFO",
            f"Total IOCs found : {summary.get('total_iocs', 0)}")
        print_finding("INFO",
            f"Critical IOCs    : {summary.get('critical_count', 0)}")
        print_finding("INFO",
            f"C2 indicators    : {summary.get('has_c2_indicators')}")
        print_finding("INFO",
            f"Financial IOCs   : {summary.get('has_financial_indicators')}")

        iocs = ioc_result.get('iocs', {})

        ioc_display_map = {
            "ipv4_address":        ("🌐 IP Addresses",         "CRITICAL"),
            "domain":              ("🔗 Domains",              "HIGH"),
            "url_full":            ("📡 Full URLs",            "HIGH"),
            "api_endpoint":        ("🔌 API Endpoints",        "MEDIUM"),
            "websocket_url":       ("⚡ WebSocket URLs",       "CRITICAL"),
            "onion_address":       ("🧅 Tor/Onion Addresses",  "CRITICAL"),
            "google_api_key":      ("🔑 Google API Keys",      "HIGH"),
            "aws_access_key":      ("🔑 AWS Access Keys",      "CRITICAL"),
            "firebase_key":        ("🔑 Firebase URLs",        "HIGH"),
            "api_key_generic":     ("🔑 Generic API Keys",     "CRITICAL"),
            "jwt_token":           ("🎫 JWT Tokens",           "CRITICAL"),
            "hardcoded_password":  ("🔐 Hardcoded Passwords",  "CRITICAL"),
            "private_key":         ("🔐 Private Keys",         "CRITICAL"),
            "email_address":       ("📧 Email Addresses",      "HIGH"),
            "phone_number":        ("📞 Phone Numbers",        "MEDIUM"),
            "indian_mobile":       ("📞 Indian Mobile Numbers","HIGH"),
            "crypto_bitcoin":      ("₿  Bitcoin Wallets",      "CRITICAL"),
            "crypto_ethereum":     ("Ξ  Ethereum Wallets",     "CRITICAL"),
            "database_connection": ("🗄️  DB Connections",       "CRITICAL"),
            "c2_port":             ("🚨 Suspicious C2 Ports",  "CRITICAL"),
        }

        for ioc_type, (display_name, severity) in ioc_display_map.items():
            findings = iocs.get(ioc_type, [])
            if not findings:
                continue

            print_finding(severity, f"{display_name}: {len(findings)} found")
            for f in findings[:5]:
                val  = f.get('value', '')[:80]
                src  = f.get('source', '')[-40:]
                note = f.get('investigation_note', '')[:60]
                print(f"             VALUE   : {val}")
                print(f"             SOURCE  : {src}")
                if note:
                    print(f"             NOTE    : {note}")
                print()

        results['iocs'] = ioc_result
        print("\n  ✅ Module 6 PASSED")

    except Exception as e:
        print(f"  ❌ Module 6 FAILED: {e}")
        import traceback; traceback.print_exc()

    # ══════════════════════════════════════════════════════════
    # MODULE 7: Manifest Deep Analysis
    # ══════════════════════════════════════════════════════════
    print_section("MODULE 7: ANDROIDMANIFEST.XML DEEP ANALYSIS")
    try:
        from analyzer.static.manifest_parser import ManifestParser

        if apk_obj:
            manifest_parser = ManifestParser(apk_obj)
            manifest_result = manifest_parser.parse()

            components  = manifest_result.get('components', {})
            attack_surf = manifest_result.get('exported_attack_surface', {})
            misconfigs  = manifest_result.get('misconfigurations', [])

            print_finding("INFO",
                f"Activities : {len(components.get('activities', []))}")
            print_finding("INFO",
                f"Services   : {len(components.get('services', []))}")
            print_finding("INFO",
                f"Receivers  : {len(components.get('receivers', []))}")
            print_finding("INFO",
                f"Providers  : {len(components.get('providers', []))}")

            exported_act = attack_surf.get('activities', [])
            exported_svc = attack_surf.get('services', [])
            exported_rcv = attack_surf.get('receivers', [])

            if exported_act:
                print_finding("HIGH",
                    f"Exported Activities ({len(exported_act)}) - Attack Surface:")
                for a in exported_act:
                    print(f"             → {a.get('name', a)}")

            if exported_svc:
                print_finding("HIGH",
                    f"Exported Services ({len(exported_svc)}) - Attack Surface:")
                for s in exported_svc:
                    print(f"             → {s.get('name', s)}")

            if exported_rcv:
                print_finding("MEDIUM",
                    f"Exported Receivers ({len(exported_rcv)}):")
                for r in exported_rcv:
                    print(f"             → {r.get('name', r)}")

            if misconfigs:
                print_finding("HIGH",
                    f"Misconfigurations: {len(misconfigs)}")
                for m in misconfigs:
                    print(f"             → {m}")

            results['manifest'] = manifest_result
            print("\n  ✅ Module 7 PASSED")
        else:
            print("  ⚠️  Skipped - Androguard not loaded")

    except Exception as e:
        print(f"  ❌ Module 7 FAILED: {e}")
        import traceback; traceback.print_exc()

    # ══════════════════════════════════════════════════════════
    # MODULE 8: Code Analysis
    # ══════════════════════════════════════════════════════════
    print_section("MODULE 8: DECOMPILED CODE RISK ANALYSIS")
    try:
        from analyzer.static.code_analyzer import CodeAnalyzer

        # CodeAnalyzer expects Dict[str, str] of filename -> code content.
        # Without JADX, we feed raw extracted strings as a synthetic file.
        java_files = results.get('decompiled', {}).get('java_files', {})
        raw_strings = _extract_raw_strings(apk_path)
        string_blob = "\n".join(raw_strings)
        if string_blob:
            java_files["__strings_dump__"] = string_blob

        if java_files:
            code_analyzer = CodeAnalyzer(java_files)
            code_result   = code_analyzer.analyze()

            capabilities = code_result.get('capabilities', [])
            risk_score   = code_result.get('code_risk_score', 0)

            print_finding("INFO", f"Code risk score : {risk_score}/100")
            print_finding("INFO", f"Capabilities    : {len(capabilities)}")

            risky = code_result.get('risky_api_findings', {})

            for api_category, findings in risky.items():
                if not findings:
                    continue
                print_finding("HIGH",
                    f"{api_category.upper()}: {len(findings)} occurrences")
                for f in findings[:3]:
                    ctx = f.get('context', '')[:80].replace('\n', ' ')
                    print(f"             File    : {f.get('file', 'unknown')}")
                    print(f"             Pattern : {f.get('match', '')}")
                    print(f"             Context : ...{ctx}...")
                    print()

            print_subsection("Detected Capabilities")
            for cap in capabilities:
                sev = cap.get('risk', 'MEDIUM')
                print_finding(sev,
                    f"{cap.get('capability')} "
                    f"(evidence: {cap.get('evidence_count')})")
                print(f"             {cap.get('description', '')}")

            obf = code_result.get('obfuscation', {})
            if obf.get('is_obfuscated'):
                print_finding("HIGH",
                    f"OBFUSCATED CODE DETECTED! "
                    f"{obf.get('obfuscation_percentage')}% obfuscated")
                print_finding("HIGH",
                    f"Detected packers: {obf.get('detected_packers')}")
            else:
                print_finding("OK", "No heavy obfuscation detected")

            results['code_analysis'] = code_result
            print("\n  ✅ Module 8 PASSED")
        else:
            print("  ⚠️  No code sources available for analysis")

    except Exception as e:
        print(f"  ❌ Module 8 FAILED: {e}")
        import traceback; traceback.print_exc()
    # ══════════════════════════════════════════════════════════
    # MODULE 8B: NESTED APK / DROPPER DETECTION
    # ══════════════════════════════════════════════════════════
    print_section("MODULE 8B: NESTED APK & HIDDEN PAYLOAD DISCOVERY")
    try:
        from analyzer.static.nested_apk_detector import NestedAPKDetector

        detector      = NestedAPKDetector(apk_path, output_dir)
        nested_result = detector.run()

        summary = nested_result.get('summary', {})
        dropper = nested_result.get('dropper_indicators', {})

        print_finding("INFO",
            f"Hidden payloads found    : {nested_result['total_hidden_payloads']}")
        print_finding("INFO",
            f"Dropper code patterns    : {len(nested_result.get('code_patterns', []))}")
        print_finding("INFO",
            f"Dropper classification   : {dropper.get('classification')}")
        print_finding("INFO",
            f"Dropper confidence       : {dropper.get('dropper_confidence', 0)}%")

        if dropper.get('dropper_confidence', 0) >= 40:
            print_finding("CRITICAL", f"⚠️  DROPPER MALWARE CONFIRMED")
            print(f"\n    {dropper.get('explanation', '')}\n")

        # Show each found payload
        payloads = nested_result.get('payloads', [])
        for idx, payload in enumerate(payloads, 1):
            print_subsection(f"HIDDEN PAYLOAD #{idx}: {payload.get('source_path')}")

            print_finding(
                "CRITICAL" if payload.get('is_disguised') else "HIGH",
                f"File      : {payload.get('source_path')}"
            )
            print_finding("INFO",
                f"Type      : {payload.get('file_type')}")
            print_finding("INFO",
                f"Size      : {payload.get('size_kb')} KB")
            print_finding("INFO",
                f"Entropy   : {payload.get('entropy')}")
            print_finding("INFO",
                f"Disguised : {payload.get('is_disguised')} "
                f"(ext: {payload.get('disguise_ext')} → actual: {payload.get('file_type')})")
            print_finding("INFO",
                f"MD5       : {payload.get('hashes', {}).get('md5')}")
            print_finding("INFO",
                f"SHA256    : {payload.get('hashes', {}).get('sha256')}")
            print_finding("INFO",
                f"Saved to  : {payload.get('extracted_to')}")

            analysis = payload.get('analysis', {})

            if analysis.get('type') == 'NESTED_APK':
                print(f"\n    {'─'*50}")
                print(f"    📱 NESTED APK CONTENTS:")
                print(f"    {'─'*50}")
                print_finding("INFO",
                    f"Valid APK     : {analysis.get('is_valid_zip')}")
                print_finding("INFO",
                    f"File count    : {analysis.get('file_count')}")
                print_finding("INFO",
                    f"Has Manifest  : {analysis.get('has_manifest')}")
                print_finding("INFO",
                    f"DEX files     : {len(analysis.get('dex_files', []))}")
                print_finding("INFO",
                    f"Native libs   : {len(analysis.get('native_libs', []))}")

                # Nested package info
                ag_meta = analysis.get('androguard_meta')
                if ag_meta:
                    print(f"\n    📋 NESTED APK METADATA:")
                    print_finding("CRITICAL",
                        f"Package  : {ag_meta.get('package_name')}")
                    print_finding("INFO",
                        f"Version  : {ag_meta.get('version')}")
                    print_finding("INFO",
                        f"Min SDK  : {ag_meta.get('min_sdk')}")

                    nested_perms = ag_meta.get('permissions', [])
                    if nested_perms:
                        print_finding("CRITICAL",
                            f"Permissions ({len(nested_perms)}):")
                        for p in nested_perms[:10]:
                            print(f"               → {p}")

                    nested_activities = ag_meta.get('activities', [])
                    if nested_activities:
                        print_finding("INFO",
                            f"Activities: {len(nested_activities)}")
                        for act in nested_activities[:5]:
                            print(f"               → {act}")

                    nested_services = ag_meta.get('services', [])
                    if nested_services:
                        print_finding("HIGH",
                            f"Services: {len(nested_services)}")
                        for svc in nested_services[:5]:
                            print(f"               → {svc}")

                # Permission risk
                perm_risk = analysis.get('permission_risk', {})
                if perm_risk:
                    print_finding(
                        perm_risk.get('grade', 'INFO'),
                        f"Risk Score: {perm_risk.get('score', 0)}%"
                    )
                    dangerous = perm_risk.get('dangerous', [])
                    if dangerous:
                        for p in dangerous[:5]:
                            print(f"               → {p}")

        results['nested_analysis'] = nested_result
        print("\n  ✅ Module 8B PASSED")

    except Exception as e:
        print(f"  ❌ Module 8B FAILED: {e}")
        import traceback; traceback.print_exc()

    # ══════════════════════════════════════════════════════════
    # MODULE 8C: PACKER & PAYLOAD DETECTION
    # ══════════════════════════════════════════════════════════
    print_section("MODULE 8C: PACKER & ENCRYPTED PAYLOAD DETECTION")
    try:
        from analyzer.static.packer_detector import PackerDetector

        p_detector = PackerDetector(apk_path, output_dir)
        packer_result = p_detector.analyze()

        if packer_result.get('is_packed'):
            packers = packer_result.get('detected_packers', [])
            print_finding("CRITICAL", f"⚠️  COMMERCIAL/MALWARE PACKER DETECTED")
            for p in packers:
                print(f"             → {p}")
        else:
            print_finding("OK", "No known packer signatures found")

        blobs = packer_result.get('encrypted_blobs', [])
        if blobs:
            print_finding("HIGH", f"Found {len(blobs)} highly-entropic, large asset blobs")
            for b in blobs:
                print_subsection(f"BLOB: {b.get('path')}")
                print_finding("INFO", f"Size    : {b.get('size_kb')} KB")
                print_finding("WARN" if b.get('entropy') > 7.8 else "INFO", f"Entropy : {b.get('entropy')} (Encrypted/Compressed)")
                
                hits = b.get('xor_header_hits', [])
                if hits:
                    print_finding("CRITICAL", f"⚠️ XOR Brute-Force Successful!")
                    for hit in hits:
                        print(f"             → Key: {hit['key_hex']} reveals {hit['revealed_type']}")
        
        results['packer_analysis'] = packer_result
        print("\n  ✅ Module 8C PASSED")

    except Exception as e:
        print(f"  ❌ Module 8C FAILED: {e}")
        import traceback; traceback.print_exc()

    # ══════════════════════════════════════════════════════════
    # MODULE 9: VirusTotal Check
    # ══════════════════════════════════════════════════════════
    print_section("MODULE 9: VIRUSTOTAL REPUTATION CHECK")
    try:
        from config import settings
        vt_api_key = settings.VIRUSTOTAL_API_KEY or os.environ.get('VIRUSTOTAL_API_KEY', '')
        if not vt_api_key:
            print_finding("WARN",
                "VIRUSTOTAL_API_KEY not set - skipping VT check")
            print("  Set via: config.py or $env:VIRUSTOTAL_API_KEY")
        else:
            import asyncio
            from intelligence.virustotal import VirusTotalClient

            sha256  = results.get('file_metadata', {}).get('hashes', {}).get('sha256')
            vt      = VirusTotalClient(vt_api_key)
            vt_result = asyncio.run(vt.check_hash(sha256))

            detections = vt_result.get('positives', 0)
            total      = vt_result.get('total', 0)

            if detections > 0:
                print_finding("CRITICAL",
                    f"MALWARE DETECTED: {detections}/{total} engines flagged!")
                for engine, result in vt_result.get('scans', {}).items():
                    if result.get('detected'):
                        print(f"             → {engine}: {result.get('result')}")
            else:
                print_finding("OK",
                    f"Clean: 0/{total} engines flagged (or not in VT database)")

            results['virustotal'] = vt_result

    except Exception as e:
        print(f"  ⚠️  VT check skipped: {e}")

    # ══════════════════════════════════════════════════════════
    # MODULE 10: DYNAMIC ANALYSIS (PCAP CAPTURE)
    # ══════════════════════════════════════════════════════════
    print_section("MODULE 10: DYNAMIC ANALYSIS (PCAP CAPTURE)")
    try:
        from analyzer.dynamic.dynamic_engine import DynamicEngine
        pkg_name = results.get('apk_metadata', {}).get('package_name', 'unknown')
        
        dynamic_engine = DynamicEngine(apk_path=apk_path, package_name=pkg_name, duration=15)
        
        if dynamic_engine.check_environment():
            dyn_result = dynamic_engine.run_analysis()
            
            traffic = dyn_result.get('network_traffic', {})
            if 'error' in traffic:
                print(f"  ⚠️  Dynamic capture error: {traffic['error']}")
            else:
                summary = traffic.get('summary', {})
                print_finding("INFO", f"Captured packets : {summary.get('total_packets', 0)}")
                print_finding("INFO", f"Unique IPs       : {summary.get('unique_ips_count', 0)}")
                print_finding("INFO", f"DNS Queries      : {summary.get('dns_query_count', 0)}")
                
                dns = traffic.get('dns_queries', [])
                if dns:
                    print_finding("HIGH", f"DNS Beacons detected ({len(dns)}):")
                    for d in dns[:5]:
                        print(f"             → {d}")
                        
            results['dynamic_analysis'] = dyn_result
            print("\n  ✅ Module 10 PASSED")
        else:
            print("  ⚠️  Skipped - No Emulator/Device connected via ADB")
            
    except Exception as e:
        print(f"  ❌ Module 10 FAILED: {e}")
        import traceback; traceback.print_exc()

    # ══════════════════════════════════════════════════════════
    # MODULE 11: THREAT SCORING & SUMMARY
    # ══════════════════════════════════════════════════════════
    print_section("MODULE 11: THREAT SCORING & INVESTIGATION SUMMARY")

    threat_score  = 0
    threat_factors = []

    # Score from permissions
    perm_risk = results.get('permissions', {}).get('risk_percentage', 0)
    threat_score += perm_risk * 0.3
    if perm_risk > 60:
        threat_factors.append(f"High-risk permissions ({perm_risk}% risk score)")

    # Score from dangerous combos
    combos = results.get('permissions', {}).get('dangerous_combinations', [])
    threat_score += len(combos) * 15
    for c in combos:
        threat_factors.append(f"Dangerous permission combo: {c['name']}")

    # Score from code analysis
    code_risk = results.get('code_analysis', {}).get('code_risk_score', 0)
    threat_score += code_risk * 0.3
    caps = results.get('code_analysis', {}).get('capabilities', [])
    for cap in caps:
        if cap.get('risk') == 'CRITICAL':
            threat_score  += 20
            threat_factors.append(f"Critical code capability: {cap['capability']}")

    # Score from IOCs
    ioc_summary = results.get('iocs', {}).get('summary', {})
    if ioc_summary.get('has_c2_indicators'):
        threat_score  += 25
        threat_factors.append("C2 communication indicators found")
    if ioc_summary.get('has_financial_indicators'):
        threat_score  += 30
        threat_factors.append("Financial crime indicators (crypto wallets)")
    threat_score += ioc_summary.get('critical_count', 0) * 3

    # Score from Dynamic Analysis
    dyn_res = results.get('dynamic_analysis', {}).get('network_traffic', {})
    if dyn_res and 'error' not in dyn_res:
        dns_queries = dyn_res.get('dns_queries', [])
        unique_ips = dyn_res.get('unique_ips', [])
        if dns_queries or unique_ips:
            threat_score += 25
            threat_factors.append(f"Dynamic C2 Beacons Detected ({len(dns_queries)} DNS, {len(unique_ips)} IPs)")

    # Score from Nested APK / Droppers
    nested_res = results.get('nested_analysis', {})
    if nested_res:
        dropper = nested_res.get('dropper_indicators', {})
        dropper_conf = dropper.get('dropper_confidence', 0)
        threat_score += dropper_conf * 0.5
        if dropper_conf >= 40:
            threat_factors.append(f"Confirmed Dropper Behavior ({dropper_conf}% confidence)")
        for payload in nested_res.get('payloads', []):
            if payload.get('is_disguised'):
                threat_score += 15
                threat_factors.append(f"Disguised hidden payload detected: {payload.get('source_path')}")

    # Score from Packer Analysis
    packer_res = results.get('packer_analysis', {})
    if packer_res:
        if packer_res.get('is_packed'):
            threat_score += 40
            packers_list = ", ".join(packer_res.get('detected_packers', []))
            threat_factors.append(f"App is packed/protected with: {packers_list}")
            
        blobs = packer_res.get('encrypted_blobs', [])
        for b in blobs:
            threat_score += 10
            threat_factors.append(f"Highly-entropic encrypted blob detected: {b.get('path')} ({b.get('size_kb')} KB)")
            if b.get('xor_header_hits'):
                threat_score += 20
                threat_factors.append(f"XOR-obfuscated executable header found in {b.get('path')}!")

    # Score from VirusTotal
    vt_res = results.get('virustotal', {})
    if vt_res:
        positives = vt_res.get('positives', 0)
        if positives > 0:
            # 10 points per engine detection, capped at 60 points max
            threat_score += min(positives * 10, 60)
            threat_factors.append(f"VirusTotal detected malware ({positives}/{vt_res.get('total', 0)} engines)")

    # Cap at 100
    threat_score = min(int(threat_score), 100)

    # Grade
    if threat_score >= 80:
        grade       = "CRITICAL"
        grade_icon  = "🔴"
        verdict     = "HIGH PROBABILITY MALWARE / MALICIOUS APP"
    elif threat_score >= 60:
        grade       = "HIGH"
        grade_icon  = "🟠"
        verdict     = "SUSPICIOUS - LIKELY MALICIOUS"
    elif threat_score >= 40:
        grade       = "MEDIUM"
        grade_icon  = "🟡"
        verdict     = "POTENTIALLY UNWANTED APPLICATION"
    elif threat_score >= 20:
        grade       = "LOW"
        grade_icon  = "🟢"
        verdict     = "LOW RISK - MONITOR"
    else:
        grade       = "CLEAN"
        grade_icon  = "✅"
        verdict     = "LIKELY LEGITIMATE"

    print(f"\n  {'─'*60}")
    print(f"  {grade_icon} THREAT SCORE : {threat_score}/100")
    print(f"  {grade_icon} RISK GRADE   : {grade}")
    print(f"  {grade_icon} VERDICT      : {verdict}")
    print(f"  {'─'*60}")

    print_subsection("Risk Factors Identified")
    if threat_factors:
        for i, factor in enumerate(threat_factors, 1):
            print(f"    {i:02d}. {factor}")
    else:
        print("    No significant risk factors detected")

    apk_meta = results.get('apk_metadata', {})
    cert_data = results.get('certificate', {})
    attribution = cert_data.get('attribution_clues', {}) if cert_data else {}

    print_subsection("INVESTIGATION SUMMARY")
    print(f"""
    App Name    : {apk_meta.get('app_name', 'N/A')}
    Package     : {apk_meta.get('package_name', 'N/A')}
    Version     : {apk_meta.get('version_name', 'N/A')}
    Developer   : {attribution.get('developer_name', 'Unknown')}
    Org         : {attribution.get('organization', 'Unknown')}
    Country     : {attribution.get('country', 'Unknown')}
    Permissions : {len(apk_meta.get('permissions', []))} total
    IOCs Found  : {ioc_summary.get('total_iocs', 0)} artifacts
    Risk Score  : {threat_score}/100 ({grade})
    """)

    # ══════════════════════════════════════════════════════════
    # MODULE 12: AI THREAT ANALYSIS (OPTIONAL)
    # ══════════════════════════════════════════════════════════
    print_section("MODULE 12: AI THREAT ANALYSIS (GEMINI / OPENAI)")
    try:
        from intelligence.ai_analyzer import AIAnalyzer
        ai_analyzer = AIAnalyzer()
        
        if ai_analyzer.client:
            print("  [*] Sending forensic JSON data to AI for orchestration...")
            ai_report = ai_analyzer.analyze_report(results)
            
            if "error" in ai_report:
                print(f"  ❌ AI Analysis Failed: {ai_report['error']}")
            else:
                print("\n  🧠 AI VERDICT             :", ai_report.get('verdict'))
                print(f"  🧠 AI THREAT SCORE          : {ai_report.get('threat_score_override')}/100")
                print(f"  🧠 MALWARE FAMILY HYPOTHESIS: {ai_report.get('malware_family_hypothesis')}\n")
                
                print_subsection("Executive Summary (AI Generated)")
                print(f"    {ai_report.get('executive_summary', '')}\n")
                
                print_subsection("Key AI Findings")
                for kf in ai_report.get('key_findings', []):
                    print(f"    → {kf}")
                
                print_subsection("MITRE ATT&CK Tactics")
                for tactic in ai_report.get('mitre_attck_tactics', []):
                    print(f"    → {tactic}")

                # Override Threat Score with AI's contextual score if present
                if isinstance(ai_report.get('threat_score_override'), int):
                    threat_score = ai_report['threat_score_override']
                    
                results['ai_analysis'] = ai_report
                print("\n  ✅ Module 11 PASSED")
        else:
            print("  ⚠️  Skipped - No GEMINI_API_KEY environment variable found.")
            print("  To enable, run: $env:GEMINI_API_KEY='your_api_key'")

    except Exception as e:
        print(f"  ❌ Module 11 FAILED: {e}")
        import traceback; traceback.print_exc()

    # ══════════════════════════════════════════════════════════
    # SAVE FULL REPORT AS JSON
    # ══════════════════════════════════════════════════════════
    print_section("SAVING ANALYSIS REPORT")

    results['threat_assessment'] = {
        "score":   threat_score,
        "grade":   grade,
        "verdict": verdict,
        "factors": threat_factors
    }
    results['analysis_metadata'] = {
        "tool":        "ForensicDroid v1.0",
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
        "apk_path":    apk_path,
    }

    def clean_for_json(obj):
        if isinstance(obj, set):
            return list(obj)
        if hasattr(obj, '__dict__'):
            return str(obj)
        return str(obj)

    report_path = os.path.join(output_dir, "forensic_report.json")
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, default=clean_for_json, ensure_ascii=False)

    print_finding("OK",   f"JSON report saved: {report_path}")
    print_finding("INFO", f"Report size: {os.path.getsize(report_path) / 1024:.1f} KB")

    print_section("ANALYSIS COMPLETE")
    print(f"""
  📋 Summary:
     APK      : {apk_name}
     Risk     : {grade_icon} {grade} ({threat_score}/100)
     Verdict  : {verdict}
     Report   : {report_path}

  Next Steps:
     1. Review full report JSON: {report_path}
     2. Check flagged IOCs against threat intelligence
     3. Run dynamic analysis with PCAP capture
     4. Generate PDF forensic report via web interface
    """)

    return results


# ─── Helper Functions ─────────────────────────────────────────
def _classify_file(filename: str) -> str:
    ext_map = {
        ".dex":    "dalvik_bytecode",
        ".xml":    "xml_resource",
        ".so":     "native_library",
        ".png":    "image",
        ".jpg":    "image",
        ".json":   "json_data",
        ".db":     "database",
        ".sqlite": "database",
        ".js":     "javascript",
        ".html":   "html",
        ".cer":    "certificate",
        ".pem":    "certificate",
        ".rsa":    "signature",
        ".sf":     "signature_file",
        ".mf":     "manifest",
        ".kotlin_module": "kotlin_metadata",
        ".proto":  "protobuf",
    }
    ext = Path(filename).suffix.lower()
    return ext_map.get(ext, "unknown")


def _is_suspicious(filename: str) -> bool:
    fname = filename.lower()
    flags = [
        "payload", "shell", "inject", "exploit",
        "backdoor", "keylog", "hook", "root",
        "busybox", "daemon"
    ]
    if fname.endswith(".so") and not fname.startswith("lib/"):
        return True
    if fname.endswith(".dex") and fname not in [
        "classes.dex", "classes2.dex", "classes3.dex"
    ]:
        return True
    return any(f in fname for f in flags)


def _get_flag(filename: str) -> str:
    fname = filename.lower()
    if any(k in fname for k in ["secret", "key", "token", "password", "cred"]):
        return "CREDENTIAL_FILE"
    if fname.endswith((".db", ".sqlite")):
        return "DATABASE_FILE"
    if fname.endswith(".so"):
        return "NATIVE_CODE"
    if "assets" in fname and fname.endswith(".json"):
        return "CONFIG_FILE"
    return None


def _extract_raw_strings(apk_path: str) -> list:
    """Extract printable strings from raw APK binary"""
    import re
    import zipfile

    strings = []
    min_len = 6

    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            for name in zf.namelist():
                if name.endswith(('.dex', '.xml', '.json', '.js')):
                    try:
                        data = zf.read(name)
                        ascii_strings = re.findall(
                            rb'[\x20-\x7E]{' + str(min_len).encode() + rb',}',
                            data
                        )
                        strings.extend([
                            s.decode('ascii', errors='ignore')
                            for s in ascii_strings
                        ])
                    except Exception:
                        continue
    except Exception as e:
        print(f"    ⚠️  String extraction warning: {e}")

    return strings[:50000]


# ─── Entry Point ──────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_analyzer.py <path_to_apk>")
        print("Example: python test_analyzer.py malware.apk")
        sys.exit(1)

    apk_path = " ".join(sys.argv[1:])

    try:
        results = run_full_analysis(apk_path)
    except KeyboardInterrupt:
        print("\n\n⚠️  Analysis interrupted by user")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
