from app.models import Decision
from app.approvals import approvals
from app.dlp import inspect
LEVEL={"public":0,"internal":1,"confidential":2,"restricted":3}
class PolicyEngine:
    def evaluate(self,p,t,r):
        pol=t.policy; reasons=[]; obligations=[]
        if not pol.enabled:return Decision(outcome="deny",reasons=["tool disabled"])
        if pol.tenant not in {"global",p.tenant}:return Decision(outcome="deny",reasons=["tenant mismatch"])
        missing=[s for s in pol.required_scopes if s not in p.scopes]
        if missing:return Decision(outcome="deny",reasons=[f"missing scopes: {','.join(missing)}"])
        if r.context_integrity=="untrusted" and not pol.accepts_untrusted:
            return Decision(outcome="deny",reasons=["untrusted context cannot flow to this tool"])
        if LEVEL[r.confidentiality]>LEVEL[pol.max_input_confidentiality]:
            return Decision(outcome="deny",reasons=["confidentiality exceeds tool policy"])
        findings=inspect(r.arguments)
        if findings:
            return Decision(outcome="deny",reasons=["DLP findings: "+",".join(findings)])
        need=pol.approval=="always" or (pol.approval=="write" and pol.risk in {"write","destructive","secret"})
        if need:
            if not r.approval_token or not approvals.verify(r.approval_token,p,t,r.arguments):
                return Decision(outcome="approval_required",reasons=["bound approval required"],obligations=["obtain human approval"])
        return Decision(outcome="allow",reasons=["policy satisfied"],obligations=obligations)
policy=PolicyEngine()
