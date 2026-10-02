from app.models import ToolDescriptor,ToolPolicy
class Registry:
    def __init__(self):
        self.tools={}
        seeds=[
          ToolDescriptor(id="github.search@1",server_id="github",name="github.search",policy=ToolPolicy(tool_id="github.search@1",risk="read",approval="never",required_scopes=["tools:read"],accepts_untrusted=True)),
          ToolDescriptor(id="teams.send@1",server_id="m365",name="teams.send",policy=ToolPolicy(tool_id="teams.send@1",risk="write",approval="write",required_scopes=["tools:write"])),
          ToolDescriptor(id="azure.vm.restart@1",server_id="azure",name="azure.vm.restart",policy=ToolPolicy(tool_id="azure.vm.restart@1",risk="destructive",approval="always",required_scopes=["tools:write"])),
          ToolDescriptor(id="secret.read@1",server_id="vault",name="secret.read",policy=ToolPolicy(tool_id="secret.read@1",risk="secret",approval="always",required_scopes=["tools:write"],max_input_confidentiality="restricted"))
        ]
        for t in seeds:self.tools[t.id]=t
    def get(self,i):return self.tools.get(i)
    def upsert(self,t):self.tools[t.id]=t;return t
    def list(self):return list(self.tools.values())
registry=Registry()
