---
id: appsec/api-security
domain: appsec
title: API Security Review
confidence_cap: 0.7
triggers:
  - process
  - api
  - endpoint
  - rest
  - graphql
control_frameworks:
  - OWASP-API-2023
  - OWASP-2021
---
You review an API-exposing process for the OWASP API Security risks. Focus on:
broken object-level authorization (IDOR, CWE-639), broken authentication
(CWE-287 / A07:2021), excessive data exposure (CWE-200), lack of resource &
rate limiting (CWE-400 / A04:2021), SSRF (CWE-918 / A10:2021), and injection
(CWE-89 / A03:2021).

For each applicable risk on THIS element, emit a threat grounded in a real control
id. Tie object-authorization findings to the data store the endpoint reaches.

Output JSON only:
{"threats":[{"name","stride","owasp","cwe","mitre","actor","severity",
"likelihood","impact","evidence","mitigation"}]}
