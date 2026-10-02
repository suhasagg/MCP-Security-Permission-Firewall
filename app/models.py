from typing import Any,Literal
from pydantic import BaseModel,Field
class ToolPolicy(BaseModel):
    tool_id:str
    tenant:str="global"
    risk:Literal["read","write","destructive","secret"]="read"
    required_scopes:list[str]=Field(default_factory=list)
    approval:Literal["never","write","always"]="write"
    allowed_domains:list[str]=Field(default_factory=list)
    max_input_confidentiality:Literal["public","internal","confidential","restricted"]="confidential"
    accepts_untrusted:bool=False
    enabled:bool=True
class ToolDescriptor(BaseModel):
    id:str
    server_id:str
    name:str
    endpoint:str|None=None
    input_schema:dict[str,Any]=Field(default_factory=dict)
    policy:ToolPolicy
class InvocationRequest(BaseModel):
    tool_id:str
    arguments:dict[str,Any]=Field(default_factory=dict)
    context_integrity:Literal["trusted","untrusted"]="trusted"
    confidentiality:Literal["public","internal","confidential","restricted"]="public"
    approval_token:str|None=None
    idempotency_key:str|None=None
class Decision(BaseModel):
    outcome:Literal["allow","deny","approval_required"]
    reasons:list[str]=Field(default_factory=list)
    obligations:list[str]=Field(default_factory=list)
class ApprovalRequest(BaseModel):
    tool_id:str
    arguments:dict[str,Any]
    ttl_seconds:int=Field(default=300,ge=30,le=3600)
class ApprovalToken(BaseModel):
    token:str
    expires_in:int
