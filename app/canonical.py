import json,hashlib
def canonical_json(v): return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)
def sha256_obj(v): return hashlib.sha256(canonical_json(v).encode()).hexdigest()
