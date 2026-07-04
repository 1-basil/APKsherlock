"""
Compares what the APK's code *says* it talks to (static strings)
against what it *actually* talked to at runtime (dynamic capture).

The most forensically interesting bucket is `dynamic_only`: servers the
app contacted that were never hardcoded anywhere in the decompiled
code. That's a strong signal of a remotely-fetched C2 address or
server-driven config — exactly the kind of inconsistency the problem
statement asks you to flag.
"""


def correlate(static_iocs, dynamic_iocs):
    static_domains = set(static_iocs.get("domain", [])) | set(static_iocs.get("url", []))
    static_ips = set(static_iocs.get("ip", []))

    dynamic_domains = set(dynamic_iocs.get("domains", []))
    dynamic_ips = set(dynamic_iocs.get("dest_ips", []))

    return {
        "confirmed_domains": sorted(static_domains & dynamic_domains),
        "confirmed_ips": sorted(static_ips & dynamic_ips),
        "static_only_domains": sorted(static_domains - dynamic_domains),
        "static_only_ips": sorted(static_ips - dynamic_ips),
        "dynamic_only_domains": sorted(dynamic_domains - static_domains),
        "dynamic_only_ips": sorted(dynamic_ips - static_ips),
        "flag": (
            "Possible remote C2 / server-driven config: app contacted "
            "servers never referenced in the app's own code."
            if (dynamic_domains - static_domains) or (dynamic_ips - static_ips)
            else "No unexplained runtime connections detected."
        ),
    }