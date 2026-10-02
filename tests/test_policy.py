from app.registry import registry
from app.policy import policy
from app.security import Principal
from app.models import InvocationRequest
def p(scopes={"tools:read"}):return Principal("u","dev-tenant",frozenset(scopes),frozenset())
def test_read_allowed():
    d=policy.evaluate(p(),registry.get("github.search@1"),InvocationRequest(tool_id="github.search@1"))
    assert d.outcome=="allow"
def test_write_needs_scope():
    d=policy.evaluate(p(),registry.get("teams.send@1"),InvocationRequest(tool_id="teams.send@1"))
    assert d.outcome=="deny"
def test_untrusted_blocked_for_write():
    d=policy.evaluate(p({"tools:write"}),registry.get("teams.send@1"),InvocationRequest(tool_id="teams.send@1",context_integrity="untrusted"))
    assert d.outcome=="deny"
def test_dlp_blocks_secret():
    d=policy.evaluate(p(),registry.get("github.search@1"),InvocationRequest(tool_id="github.search@1",arguments={"q":"api_key=supersecretvalue123"}))
    assert d.outcome=="deny"
