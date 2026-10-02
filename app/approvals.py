import time,secrets,jwt
from app.config import settings
from app.canonical import sha256_obj
class ApprovalService:
    def issue(self,p,tool,args,ttl):
        now=int(time.time()); payload={
          "iss":"mcp-firewall","sub":p.subject,"tenant":p.tenant,"tool_id":tool.id,
          "tool_version":tool.id,"args_hash":sha256_obj(args),"iat":now,"exp":now+ttl,"nonce":secrets.token_urlsafe(16)
        }
        return jwt.encode(payload,settings.approval_signing_secret,algorithm="HS256")
    def verify(self,token,p,tool,args):
        try:
            x=jwt.decode(token,settings.approval_signing_secret,algorithms=["HS256"],issuer="mcp-firewall")
            return (x["sub"]==p.subject and x["tenant"]==p.tenant and x["tool_id"]==tool.id and x["args_hash"]==sha256_obj(args))
        except Exception:return False
approvals=ApprovalService()
