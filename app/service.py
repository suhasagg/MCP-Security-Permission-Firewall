import time
from app.registry import registry
from app.policy import policy
from app.mcp import proxy
from app.audit import emit
from app.observability import DECISIONS,INVOCATIONS,LATENCY
class Firewall:
    def evaluate(self,p,r):
        t=registry.get(r.tool_id)
        if not t:return None
        st=time.perf_counter()
        d=policy.evaluate(p,t,r)
        LATENCY.observe(time.perf_counter()-st);DECISIONS.labels(d.outcome,t.name).inc()
        emit("policy_decision",tenant=p.tenant,subject=p.subject,tool=t.id,outcome=d.outcome,reasons=d.reasons)
        return d
    async def invoke(self,p,r):
        t=registry.get(r.tool_id)
        if not t:return {"status":"error","error":"unknown tool"}
        d=self.evaluate(p,r)
        if d.outcome!="allow":
            INVOCATIONS.labels(d.outcome,t.name).inc()
            return {"status":d.outcome,"decision":d.model_dump()}
        try:
            out=await proxy.call(t,r.arguments);INVOCATIONS.labels("ok",t.name).inc()
            emit("tool_invoked",tenant=p.tenant,subject=p.subject,tool=t.id,status="ok")
            return {"status":"ok","output":out}
        except Exception as e:
            INVOCATIONS.labels("error",t.name).inc()
            emit("tool_invoked",tenant=p.tenant,subject=p.subject,tool=t.id,status="error")
            return {"status":"error","error":str(e)[:4000]}
firewall=Firewall()
