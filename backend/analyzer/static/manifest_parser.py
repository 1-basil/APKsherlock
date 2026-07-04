# backend/analyzer/static/manifest_parser.py

class ManifestParser:
    def __init__(self, apk):
        self.apk = apk

    def parse(self) -> dict:
        a = self.apk

        activities = []
        for act in a.get_activities():
            activities.append({
                "name":           act,
                "type":           "activity",
                "exported":       self._is_exported(act),
                "intent_filters": self._get_intent_filters(act)
            })

        services = []
        for svc in a.get_services():
            services.append({
                "name":           svc,
                "type":           "service",
                "exported":       self._is_exported(svc),
                "intent_filters": self._get_intent_filters(svc)
            })

        receivers = []
        for rcv in a.get_receivers():
            receivers.append({
                "name":           rcv,
                "type":           "receiver",
                "exported":       self._is_exported(rcv),
                "intent_filters": self._get_intent_filters(rcv)
            })

        providers = []
        for prv in a.get_providers():
            providers.append({
                "name":     prv,
                "type":     "provider",
                "exported": self._is_exported(prv),
                "intent_filters": []
            })

        # Exported attack surface
        exported = {
            "activities": [x for x in activities if x["exported"]],
            "services":   [x for x in services   if x["exported"]],
            "receivers":  [x for x in receivers   if x["exported"]],
            "providers":  [x for x in providers   if x["exported"]],
        }

        # Check misconfigurations
        misconfigs = []

        # Check debuggable
        try:
            app_elem = a.get_element("application", "debuggable")
            if app_elem and app_elem.lower() == "true":
                misconfigs.append({
                    "type":        "DEBUGGABLE",
                    "severity":    "HIGH",
                    "description": "Application is debuggable - allows runtime inspection",
                    "forensic":    "Attacker can attach debugger, inspect memory"
                })
        except Exception:
            pass

        # Check allowBackup
        try:
            backup = a.get_element("application", "allowBackup")
            if backup is None or backup.lower() == "true":
                misconfigs.append({
                    "type":        "ALLOW_BACKUP",
                    "severity":    "MEDIUM",
                    "description": "App data can be backed up via ADB",
                    "forensic":    "Forensic data extraction possible via: adb backup"
                })
        except Exception:
            pass

        # Check network security config
        try:
            ns_config = a.get_element("application", "networkSecurityConfig")
            if not ns_config:
                misconfigs.append({
                    "type":        "NO_NETWORK_SECURITY_CONFIG",
                    "severity":    "MEDIUM",
                    "description": "No network security configuration",
                    "forensic":    "May allow cleartext HTTP or self-signed certs"
                })
        except Exception:
            pass

        return {
            "package_name":          a.get_package(),
            "components":            {
                "activities": activities,
                "services":   services,
                "receivers":  receivers,
                "providers":  providers,
            },
            "exported_attack_surface": exported,
            "misconfigurations":     misconfigs,
            "custom_permissions":    list(a.get_declared_permissions()),
            "hardware_features":     [],
            "main_activity":         a.get_main_activity(),
        }

    def _is_exported(self, component_name: str) -> bool:
        try:
            # Check if component has intent filters (implicitly exported)
            filters = self.apk.get_intent_filters("activity", component_name)
            return len(filters) > 0
        except Exception:
            return False

    def _get_intent_filters(self, component_name: str) -> list:
        filters = []
        for comp_type in ["activity", "service", "receiver"]:
            try:
                result = self.apk.get_intent_filters(comp_type, component_name)
                if result:
                    filters.extend(result)
            except Exception:
                continue
        return filters
