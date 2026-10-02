from fastapi import FastAPI,Depends,HTTPException,Response
from prometheus_client import generate_latest,CONTENT_TYPE_LATEST
from app.models import InvocationRequest,ApprovalRequest,ApprovalToken,ToolDescriptor
from app.security import principal,require
from app.registry import registry
from app.service import firewall
from app.approvals import approvals
app=FastAPI(title="MCP Security / Permission Firewall",version="1.0.0")
@app.get("/health/live")
async def live():return {"status":"ok"}
@app.get("/v1/tools")
async def tools(p=Depends(principal)):return [t for t in registry.list() if t.policy.tenant in {"global",p.tenant}]
@app.post("/v1/evaluate")
async def evaluate(r:InvocationRequest,p=Depends(principal)):
    d=firewall.evaluate(p,r)
    if d is None:raise HTTPException(404,"unknown tool")
    return d
@app.post("/v1/invoke")
async def invoke(r:InvocationRequest,p=Depends(principal)):return await firewall.invoke(p,r)
@app.post("/v1/approvals",response_model=ApprovalToken)
async def approve(r:ApprovalRequest,p=Depends(principal)):
    require(p,"approvals:issue")
    t=registry.get(r.tool_id)
    if not t:raise HTTPException(404,"unknown tool")
    tok=approvals.issue(p,t,r.arguments,r.ttl_seconds)
    return ApprovalToken(token=tok,expires_in=r.ttl_seconds)
@app.put("/v1/admin/tools")
async def upsert(t:ToolDescriptor,p=Depends(principal)):
    require(p,"tools:admin");return registry.upsert(t)
@app.get("/metrics")
async def metrics():return Response(generate_latest(),media_type=CONTENT_TYPE_LATEST)
