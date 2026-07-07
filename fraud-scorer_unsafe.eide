#! VULNERABLE fraud-scorer — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant flag confidence 70

let raw = fetch<web>
privileged { flag(raw) }  # tainted -> tool: REJECTED
