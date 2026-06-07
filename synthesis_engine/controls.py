"""Control-framework tables + validation.

Every emitted OWASP/CWE/MITRE id is validated against these tables before it ships,
so the loop cannot invent control IDs. In production these tables are generated from
the upstream framework sources; this is a representative subset.
"""
from __future__ import annotations

OWASP_TOP_10_2021 = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}

OWASP_LLM_2025 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# Representative CWE subset (the ones our sample skills emit).
CWE = {
    "CWE-20": "Improper Input Validation",
    "CWE-79": "Cross-site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-269": "Improper Privilege Management",
    "CWE-287": "Improper Authentication",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-639": "Authorization Bypass (IDOR)",
    "CWE-918": "Server-Side Request Forgery",
}

# Representative MITRE ATT&CK techniques.
MITRE = {
    "T1190": "Exploit Public-Facing Application",
    "T1078": "Valid Accounts",
    "T1059": "Command and Scripting Interpreter",
    "T1499": "Endpoint Denial of Service",
    "T1557": "Adversary-in-the-Middle",
    "T1556": "Modify Authentication Process",
}


def resolve(control_id: str | None) -> bool:
    """True iff the id resolves in a known framework table."""
    if not control_id:
        return True  # absence is allowed; a hallucinated id is not
    cid = control_id.strip()
    return (
        cid in OWASP_TOP_10_2021
        or cid in OWASP_LLM_2025
        or cid in CWE
        or cid in MITRE
    )


def validate_threat_controls(owasp: str | None, cwe: str | None, mitre: str | None) -> list[str]:
    """Return a list of unresolved (hallucinated) ids; empty == clean."""
    bad = []
    for cid in (owasp, cwe, mitre):
        if cid and not resolve(cid):
            bad.append(cid)
    return bad
