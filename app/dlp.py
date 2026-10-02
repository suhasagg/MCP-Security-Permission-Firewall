import re
PATTERNS=[
 ("private_key",re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
 ("bearer_token",re.compile(r"(?i)bearer\s+[A-Za-z0-9._~-]{20,}")),
 ("generic_secret",re.compile(r"(?i)(api[_-]?key|password|secret)\s*[:=]\s*[^\s,;]{8,}"))
]
def inspect(value):
    text=str(value); findings=[]
    for name,p in PATTERNS:
        if p.search(text):findings.append(name)
    return findings
