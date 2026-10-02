from prometheus_client import Counter,Histogram
DECISIONS=Counter("mcp_firewall_decisions_total","Policy decisions",["outcome","tool"])
INVOCATIONS=Counter("mcp_firewall_invocations_total","Invocations",["status","tool"])
LATENCY=Histogram("mcp_firewall_policy_seconds","Policy evaluation latency")
