import httpx
from app.config import settings
class MCPProxy:
    async def call(self,t,args):
        if not t.endpoint:return {"mode":"reference","tool":t.name,"arguments":args}
        payload={"jsonrpc":"2.0","id":"fw-1","method":"tools/call","params":{"name":t.name,"arguments":args}}
        async with httpx.AsyncClient(timeout=settings.mcp_timeout_seconds,follow_redirects=False) as c:
            r=await c.post(t.endpoint,json=payload)
            r.raise_for_status()
            raw=r.content
            if len(raw)>settings.max_output_bytes: raise ValueError("MCP output exceeds configured limit")
            return r.json()
proxy=MCPProxy()
