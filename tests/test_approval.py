from app.approvals import approvals
from app.registry import registry
from app.security import Principal
def test_approval_bound_to_args():
    p=Principal("u","dev-tenant",frozenset({"tools:write"}),frozenset())
    t=registry.get("teams.send@1")
    tok=approvals.issue(p,t,{"message":"hello"},60)
    assert approvals.verify(tok,p,t,{"message":"hello"})
    assert not approvals.verify(tok,p,t,{"message":"changed"})
